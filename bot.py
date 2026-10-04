import asyncio
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
import requests

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:5000").rstrip("/")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-me")

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing from .env")
if not CLIENT_ID:
    raise RuntimeError("DISCORD_CLIENT_ID is missing from .env")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "guardian.db"

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(
    command_prefix="!",
    intents=intents,
    help_command=None,
    case_insensitive=True,
)

db_lock = threading.Lock()

# Anti-spam cache: guild -> user -> timestamps
spam_cache = defaultdict(lambda: defaultdict(lambda: deque(maxlen=20)))
anti_spam_cooldown = defaultdict(float)

LINK_RE = re.compile(
    r"(https?://\S+|www\.\S+|discord\.gg/\S+|discord(?:app)?\.com/invite/\S+)",
    re.IGNORECASE,
)

DEFAULT_SECURITY = {
    "anti_spam": 1,
    "anti_links": 1,
    "spam_limit": 6,
    "spam_window": 8,
    "timeout_minutes": 10,
    "lockdown": 0,
}


# -----------------------------
# Database
# -----------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock:
        conn = get_db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                log_channel_id INTEGER,
                anti_spam INTEGER NOT NULL DEFAULT 1,
                anti_links INTEGER NOT NULL DEFAULT 1,
                spam_limit INTEGER NOT NULL DEFAULT 6,
                spam_window INTEGER NOT NULL DEFAULT 8,
                timeout_minutes INTEGER NOT NULL DEFAULT 10,
                lockdown INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                moderator_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()


def ensure_guild(guild_id: int):
    with db_lock:
        conn = get_db()
        conn.execute(
            """
            INSERT OR IGNORE INTO guild_settings
            (guild_id, anti_spam, anti_links, spam_limit, spam_window, timeout_minutes, lockdown)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                guild_id,
                DEFAULT_SECURITY["anti_spam"],
                DEFAULT_SECURITY["anti_links"],
                DEFAULT_SECURITY["spam_limit"],
                DEFAULT_SECURITY["spam_window"],
                DEFAULT_SECURITY["timeout_minutes"],
                DEFAULT_SECURITY["lockdown"],
            ),
        )
        conn.commit()
        conn.close()


def get_settings(guild_id: int):
    ensure_guild(guild_id)
    with db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM guild_settings WHERE guild_id = ?",
            (guild_id,),
        ).fetchone()
        conn.close()
    return dict(row)


def update_settings(guild_id: int, **values):
    ensure_guild(guild_id)
    allowed = {
        "log_channel_id",
        "anti_spam",
        "anti_links",
        "spam_limit",
        "spam_window",
        "timeout_minutes",
        "lockdown",
    }
    clean = {k: v for k, v in values.items() if k in allowed}
    if not clean:
        return
    columns = ", ".join(f"{key} = ?" for key in clean)
    params = list(clean.values()) + [guild_id]
    with db_lock:
        conn = get_db()
        conn.execute(
            f"UPDATE guild_settings SET {columns} WHERE guild_id = ?",
            params,
        )
        conn.commit()
        conn.close()


def add_warning(guild_id, user_id, moderator_id, reason):
    now = int(time.time())
    with db_lock:
        conn = get_db()
        cur = conn.execute(
            """
            INSERT INTO warnings (guild_id, user_id, moderator_id, reason, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (guild_id, user_id, moderator_id, reason, now),
        )
        conn.commit()
        warning_id = cur.lastrowid
        conn.close()
    return warning_id


def get_warnings(guild_id, user_id):
    with db_lock:
        conn = get_db()
        rows = conn.execute(
            """
            SELECT * FROM warnings
            WHERE guild_id = ? AND user_id = ?
            ORDER BY id DESC
            """,
            (guild_id, user_id),
        ).fetchall()
        conn.close()
    return [dict(row) for row in rows]


def clear_warnings(guild_id, user_id):
    with db_lock:
        conn = get_db()
        cur = conn.execute(
            "DELETE FROM warnings WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        )
        conn.commit()
        count = cur.rowcount
        conn.close()
    return count


# -----------------------------
# Discord UI helpers
# -----------------------------

def footer_text():
    return "Guardian • Security first"


def base_embed(title: str, description: str = "", color: discord.Color | None = None):
    embed = discord.Embed(
        title=title,
        description=description,
        color=color or discord.Color.from_rgb(135, 91, 255),
        timestamp=discord.utils.utcnow(),
    )
    embed.set_footer(text=footer_text())
    return embed


def success(title, description):
    return base_embed(title, description, discord.Color.from_rgb(70, 210, 150))


def error_embed(title, description):
    return base_embed(title, description, discord.Color.from_rgb(245, 92, 92))


def warning_embed(title, description):
    return base_embed(title, description, discord.Color.from_rgb(245, 180, 70))


def info_embed(title, description):
    return base_embed(title, description, discord.Color.from_rgb(85, 165, 255))


def code_escape(text: str) -> str:
    return text.replace("`", "\\`")


async def send_ephemeral(interaction: discord.Interaction, embed: discord.Embed):
    if interaction.response.is_done():
        await interaction.followup.send(embed=embed, ephemeral=True)
    else:
        await interaction.response.send_message(embed=embed, ephemeral=True)


async def send_log(guild: discord.Guild, embed: discord.Embed):
    settings = get_settings(guild.id)
    channel_id = settings.get("log_channel_id")
    if not channel_id:
        return

    channel = guild.get_channel(channel_id)
    if channel is None:
        return

    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass


def can_moderate(member: discord.Member, target: discord.Member) -> bool:
    if target == member:
        return False
    if target == member.guild.owner:
        return False
    if member.guild.owner == member:
        return True
    if target == member.guild.me:
        return False
    return member.top_role > target.top_role


# -----------------------------
# Help system
# -----------------------------

class HelpView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)

    @discord.ui.button(label="Moderation", style=discord.ButtonStyle.secondary)
    async def moderation(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = base_embed(
            "🛡️ Moderation",
            "**Core server moderation commands**\n\n"
            "`/ban` — Ban a member.\n"
            "`/unban` — Remove a ban.\n"
            "`/kick` — Kick a member.\n"
            "`/timeout` — Temporarily timeout a member.\n"
            "`/untimeout` — Remove a timeout.\n"
            "`/warn` — Add a warning.\n"
            "`/warnings` — View warnings.\n"
            "`/clearwarnings` — Clear warnings.\n"
            "`/clear` — Bulk delete recent messages.",
            discord.Color.from_rgb(135, 91, 255),
        )
        await interaction.response.edit_message(embed=embed, view=self)

    @discord.ui.button(label="Security", style=discord.ButtonStyle.secondary)
    async def security(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = base_embed(
            "🔐 Security",
            "**Protection & server control**\n\n"
            "`/security` — View current security settings.\n"
            "`/setsecurity` — Configure anti-spam, anti-link and timeout values.\n"
            "`/setlog` — Choose the moderation log channel.\n"
            "`/lock` — Lock a text channel.\n"
            "`/unlock` — Unlock a text channel.\n\n"
            "**Automatic protection**\n"
            "• Anti-spam\n"
            "• Anti-link\n"
            "• Automatic timeout\n"
            "• Security event logging",
            discord.Color.from_rgb(80, 190, 170),
        )
        await interaction.response.edit_message(embed=embed, view=self)

    @discord.ui.button(label="Formatting", style=discord.ButtonStyle.secondary)
    async def formatting(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = base_embed(
            "✨ Discord Formatting",
            "**Bold**\n"
            "*Italic*\n"
            "__Underline__\n"
            "~~Strikethrough~~\n"
            "||Spoiler||\n"
            "`inline code`\n"
            "> Block quote\n\n"
            "```py\nprint(\"Hello Discord\")\n```\n\n"
            "<https://example.com>\n"
            "[Example](https://example.com)\n\n"
            "`<@USER_ID>` — user mention\n"
            "`<@&ROLE_ID>` — role mention\n"
            "`<#CHANNEL_ID>` — channel mention\n"
            "`<t:UNIX:F>` — Discord timestamp\n"
            "`<t:UNIX:R>` — relative timestamp",
            discord.Color.from_rgb(235, 170, 90),
        )
        await interaction.response.edit_message(embed=embed, view=self)

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger)
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(view=None)


@bot.tree.command(name="help", description="Open Guardian's interactive command guide.")
async def help_command(interaction: discord.Interaction):
    embed = base_embed(
        "Guardian • Help",
        "A polished **security-first** Discord bot.\n\n"
        "Use the buttons below to browse commands, security controls, "
        "and Discord's formatting syntax.\n\n"
        "```text\n"
        "Guardian is built to keep moderation fast,\n"
        "clear and good-looking.\n"
        "```",
    )
    embed.add_field(
        name="Quick start",
        value="`/security` • ` /setsecurity` • `/setlog` • `/help`",
        inline=False,
    )
    embed.add_field(
        name="Support style",
        value="Embeds • Markdown • Mentions • Code blocks • Timestamps",
        inline=False,
    )
    await interaction.response.send_message(embed=embed, view=HelpView(), ephemeral=True)


# -----------------------------
# Basic commands
# -----------------------------

@bot.tree.command(name="ping", description="Check Guardian's latency.")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    embed = success("🏓 Pong", f"WebSocket latency: **{latency}ms**")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="serverinfo", description="Show information about this server.")
async def serverinfo(interaction: discord.Interaction):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    guild = interaction.guild
    embed = info_embed("Server Information", f"### {guild.name}")
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    embed.add_field(name="Members", value=f"`{guild.member_count:,}`", inline=True)
    embed.add_field(name="Channels", value=f"`{len(guild.channels):,}`", inline=True)
    embed.add_field(name="Roles", value=f"`{len(guild.roles):,}`", inline=True)
    embed.add_field(name="Owner", value=f"<@{guild.owner_id}>", inline=True)
    embed.add_field(name="Guild ID", value=f"`{guild.id}`", inline=True)
    embed.add_field(name="Created", value=f"<t:{int(guild.created_at.timestamp())}:F>", inline=True)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="userinfo", description="Show information about a member.")
@app_commands.describe(member="The member to inspect.")
async def userinfo(interaction: discord.Interaction, member: discord.Member):
    embed = info_embed("User Information", f"### {member.display_name}")
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="Mention", value=member.mention, inline=True)
    embed.add_field(name="User ID", value=f"`{member.id}`", inline=True)
    embed.add_field(name="Joined", value=f"<t:{int(member.joined_at.timestamp())}:R>" if member.joined_at else "Unknown", inline=True)
    embed.add_field(name="Account created", value=f"<t:{int(member.created_at.timestamp())}:F>", inline=True)
    roles = [r.mention for r in member.roles[1:]]
    embed.add_field(
        name=f"Roles ({len(roles)})",
        value=" ".join(roles[-15:]) if roles else "`No roles`",
        inline=False,
    )
    await interaction.response.send_message(embed=embed)


# -----------------------------
# Moderation commands
# -----------------------------

@bot.tree.command(name="ban", description="Ban a member from the server.")
@app_commands.describe(member="Member to ban.", reason="Reason for the ban.")
@app_commands.default_permissions(ban_members=True)
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    if not can_moderate(interaction.user, member):
        return await send_ephemeral(interaction, error_embed("Action blocked", "You cannot moderate this member due to role hierarchy."))

    try:
        await member.ban(reason=f"{reason} • Moderator: {interaction.user} ({interaction.user.id})")
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot ban this member. Check role hierarchy and permissions."))
    except discord.HTTPException:
        return await send_ephemeral(interaction, error_embed("Discord error", "Discord rejected the ban request."))

    embed = success(
        "🔨 Member Banned",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="unban", description="Remove a user from the ban list.")
@app_commands.describe(user_id="The Discord user ID to unban.", reason="Reason for the unban.")
@app_commands.default_permissions(ban_members=True)
async def unban(interaction: discord.Interaction, user_id: str, reason: str = "No reason provided"):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    try:
        uid = int(user_id)
        user = await bot.fetch_user(uid)
        await interaction.guild.unban(user, reason=f"{reason} • Moderator: {interaction.user}")
    except ValueError:
        return await send_ephemeral(interaction, error_embed("Invalid ID", "Please provide a valid numeric Discord user ID."))
    except discord.NotFound:
        return await send_ephemeral(interaction, error_embed("Not found", "That user is not currently banned."))
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot remove that ban."))
    except discord.HTTPException:
        return await send_ephemeral(interaction, error_embed("Discord error", "Discord rejected the unban request."))

    embed = success(
        "✅ Ban Removed",
        f"**User:** `{user}` (`{user.id}`)\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="kick", description="Kick a member from the server.")
@app_commands.describe(member="Member to kick.", reason="Reason for the kick.")
@app_commands.default_permissions(kick_members=True)
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    if not can_moderate(interaction.user, member):
        return await send_ephemeral(interaction, error_embed("Action blocked", "You cannot moderate this member due to role hierarchy."))

    try:
        await member.kick(reason=f"{reason} • Moderator: {interaction.user} ({interaction.user.id})")
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot kick this member. Check permissions and role hierarchy."))
    except discord.HTTPException:
        return await send_ephemeral(interaction, error_embed("Discord error", "Discord rejected the kick request."))

    embed = success(
        "👢 Member Kicked",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="timeout", description="Timeout a member.")
@app_commands.describe(
    member="Member to timeout.",
    minutes="Timeout duration in minutes.",
    reason="Reason for the timeout.",
)
@app_commands.default_permissions(moderate_members=True)
async def timeout_cmd(
    interaction: discord.Interaction,
    member: discord.Member,
    minutes: app_commands.Range[int, 1, 40320],
    reason: str = "No reason provided",
):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    if not can_moderate(interaction.user, member):
        return await send_ephemeral(interaction, error_embed("Action blocked", "You cannot moderate this member due to role hierarchy."))

    try:
        await member.timeout(
            timedelta(minutes=minutes),
            reason=f"{reason} • Moderator: {interaction.user} ({interaction.user.id})",
        )
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot timeout this member."))
    except discord.HTTPException:
        return await send_ephemeral(interaction, error_embed("Discord error", "Discord rejected the timeout request."))

    embed = success(
        "⏳ Member Timed Out",
        f"**Member:** {member.mention}\n"
        f"**Duration:** `{minutes} minute(s)`\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="untimeout", description="Remove a member's timeout.")
@app_commands.describe(member="Member whose timeout should be removed.", reason="Reason.")
@app_commands.default_permissions(moderate_members=True)
async def untimeout(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    if not can_moderate(interaction.user, member):
        return await send_ephemeral(interaction, error_embed("Action blocked", "You cannot moderate this member due to role hierarchy."))

    try:
        await member.timeout(None, reason=f"{reason} • Moderator: {interaction.user} ({interaction.user.id})")
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot remove this timeout."))
    except discord.HTTPException:
        return await send_ephemeral(interaction, error_embed("Discord error", "Discord rejected the request."))

    embed = success(
        "✅ Timeout Removed",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="warn", description="Warn a member.")
@app_commands.describe(member="Member to warn.", reason="Reason for the warning.")
@app_commands.default_permissions(moderate_members=True)
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    if not can_moderate(interaction.user, member):
        return await send_ephemeral(interaction, error_embed("Action blocked", "You cannot warn this member due to role hierarchy."))

    warning_id = add_warning(interaction.guild.id, member.id, interaction.user.id, reason)
    total = len(get_warnings(interaction.guild.id, member.id))

    embed = warning_embed(
        "⚠️ Warning Added",
        f"**Member:** {member.mention}\n"
        f"**Warning:** `#{warning_id}`\n"
        f"**Total warnings:** `{total}`\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="warnings", description="View a member's warnings.")
@app_commands.describe(member="Member to inspect.")
@app_commands.default_permissions(moderate_members=True)
async def warnings(interaction: discord.Interaction, member: discord.Member):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    rows = get_warnings(interaction.guild.id, member.id)
    embed = warning_embed(
        "⚠️ Warning History",
        f"**Member:** {member.mention}\n**Total:** `{len(rows)}`",
    )

    if not rows:
        embed.description += "\n\nNo warnings found."
    else:
        lines = []
        for row in rows[:10]:
            reason = row["reason"]
            moderator = f"<@{row['moderator_id']}>"
            when = f"<t:{row['created_at']}:R>"
            lines.append(
                f"`#{row['id']}` • **{reason}**\n"
                f"Moderator: {moderator} • {when}"
            )
        embed.add_field(name="Recent warnings", value="\n\n".join(lines), inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="clearwarnings", description="Clear all warnings for a member.")
@app_commands.describe(member="Member whose warnings should be cleared.")
@app_commands.default_permissions(moderate_members=True)
async def clearwarnings(interaction: discord.Interaction, member: discord.Member):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    count = clear_warnings(interaction.guild.id, member.id)
    embed = success(
        "🧹 Warnings Cleared",
        f"Cleared **{count}** warning(s) for {member.mention}.",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="clear", description="Delete recent messages from the current channel.")
@app_commands.describe(amount="Number of messages to delete (1-100).")
@app_commands.default_permissions(manage_messages=True)
async def clear(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    if not isinstance(interaction.channel, discord.TextChannel):
        return await send_ephemeral(interaction, error_embed("Unsupported channel", "This command requires a standard text channel."))

    await interaction.response.defer(ephemeral=True)

    try:
        deleted = await interaction.channel.purge(limit=amount)
    except discord.Forbidden:
        return await interaction.followup.send(
            embed=error_embed("Permission error", "Guardian needs Manage Messages and Read Message History."),
            ephemeral=True,
        )
    except discord.HTTPException:
        return await interaction.followup.send(
            embed=error_embed("Discord error", "Discord rejected the delete request."),
            ephemeral=True,
        )

    await interaction.followup.send(
        embed=success("🧹 Messages Cleared", f"Deleted **{len(deleted)}** message(s) in {interaction.channel.mention}."),
        ephemeral=True,
    )

    log = info_embed(
        "🧹 Messages Cleared",
        f"**Channel:** {interaction.channel.mention}\n"
        f"**Amount:** `{len(deleted)}`\n"
        f"**Moderator:** {interaction.user.mention}",
    )
    await send_log(interaction.guild, log)


# -----------------------------
# Channel lock
# -----------------------------

async def set_channel_lock(channel: discord.TextChannel, locked: bool):
    everyone = channel.guild.default_role
    overwrite = channel.overwrites_for(everyone)
    overwrite.send_messages = False if locked else None
    overwrite.add_reactions = False if locked else None
    await channel.set_permissions(
        everyone,
        overwrite=overwrite,
        reason="Guardian security lock" if locked else "Guardian security unlock",
    )


@bot.tree.command(name="lock", description="Lock the current text channel.")
@app_commands.default_permissions(manage_channels=True)
async def lock(interaction: discord.Interaction):
    if not isinstance(interaction.channel, discord.TextChannel):
        return await send_ephemeral(interaction, error_embed("Unsupported channel", "This command requires a standard text channel."))

    try:
        await set_channel_lock(interaction.channel, True)
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot change permissions in this channel."))

    embed = warning_embed(
        "🔒 Channel Locked",
        f"{interaction.channel.mention} is now locked for `@everyone`.\n\n"
        "```text\n"
        "Only members with an explicit permission override\n"
        "or moderation permissions should be able to speak.\n"
        "```",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="unlock", description="Unlock the current text channel.")
@app_commands.default_permissions(manage_channels=True)
async def unlock(interaction: discord.Interaction):
    if not isinstance(interaction.channel, discord.TextChannel):
        return await send_ephemeral(interaction, error_embed("Unsupported channel", "This command requires a standard text channel."))

    try:
        await set_channel_lock(interaction.channel, False)
    except discord.Forbidden:
        return await send_ephemeral(interaction, error_embed("Permission error", "Guardian cannot change permissions in this channel."))

    embed = success(
        "🔓 Channel Unlocked",
        f"{interaction.channel.mention} is open again for `@everyone`.",
    )
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


# -----------------------------
# Security configuration
# -----------------------------

@bot.tree.command(name="security", description="Show the current security configuration.")
async def security(interaction: discord.Interaction):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    settings = get_settings(interaction.guild.id)
    log_channel = f"<#{settings['log_channel_id']}>" if settings["log_channel_id"] else "`Not configured`"

    embed = info_embed("🔐 Security Status", f"Security profile for **{interaction.guild.name}**")
    embed.add_field(name="Anti-spam", value="`ON`" if settings["anti_spam"] else "`OFF`", inline=True)
    embed.add_field(name="Anti-link", value="`ON`" if settings["anti_links"] else "`OFF`", inline=True)
    embed.add_field(name="Lockdown", value="`ON`" if settings["lockdown"] else "`OFF`", inline=True)
    embed.add_field(name="Spam limit", value=f"`{settings['spam_limit']} messages`", inline=True)
    embed.add_field(name="Spam window", value=f"`{settings['spam_window']} seconds`", inline=True)
    embed.add_field(name="Auto-timeout", value=f"`{settings['timeout_minutes']} min`", inline=True)
    embed.add_field(name="Log channel", value=log_channel, inline=False)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="setsecurity", description="Configure Guardian's security settings.")
@app_commands.describe(
    anti_spam="Enable or disable anti-spam.",
    anti_links="Enable or disable link blocking.",
    spam_limit="Messages needed within the spam window.",
    spam_window="Spam detection window in seconds.",
    timeout_minutes="Automatic timeout length when spam is detected.",
)
@app_commands.default_permissions(manage_guild=True)
async def setsecurity(
    interaction: discord.Interaction,
    anti_spam: bool,
    anti_links: bool,
    spam_limit: app_commands.Range[int, 3, 20],
    spam_window: app_commands.Range[int, 3, 30],
    timeout_minutes: app_commands.Range[int, 1, 60],
):
    if not interaction.guild:
        return await send_ephemeral(interaction, error_embed("Unavailable", "This command can only be used in a server."))

    update_settings(
        interaction.guild.id,
        anti_spam=int(anti_spam),
        anti_links=int(anti_links),
        spam_limit=int(spam_limit),
        spam_window=int(spam_window),
        timeout_minutes=int(timeout_minutes),
    )

    embed = success(
        "⚙️ Security Updated",
        "Guardian's security settings were updated successfully.",
    )
    embed.add_field(name="Anti-spam", value="`ON`" if anti_spam else "`OFF`", inline=True)
    embed.add_field(name="Anti-link", value="`ON`" if anti_links else "`OFF`", inline=True)
    embed.add_field(name="Spam limit", value=f"`{spam_limit}`", inline=True)
    embed.add_field(name="Window", value=f"`{spam_window}s`", inline=True)
    embed.add_field(name="Auto-timeout", value=f"`{timeout_minutes}m`", inline=True)
    await interaction.response.send_message(embed=embed)
    await send_log(interaction.guild, embed)


@bot.tree.command(name="setlog", description="Set the current channel as Guardian's security log.")
@app_commands.default_permissions(manage_guild=True)
async def setlog(interaction: discord.Interaction):
    if not interaction.guild or not isinstance(interaction.channel, discord.TextChannel):
        return await send_ephemeral(interaction, error_embed("Unavailable", "Run this command in a server text channel."))

    update_settings(interaction.guild.id, log_channel_id=interaction.channel.id)

    embed = success(
        "📋 Log Channel Updated",
        f"Security and moderation logs will be sent to {interaction.channel.mention}.",
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


# -----------------------------
# Anti-spam / anti-link
# -----------------------------

def mark_spam(guild_id: int, user_id: int) -> tuple[int, list[float]]:
    now = time.monotonic()
    queue = spam_cache[guild_id][user_id]
    queue.append(now)
    return len(queue), list(queue)


async def auto_timeout(member: discord.Member, minutes: int, reason: str):
    try:
        await member.timeout(timedelta(minutes=minutes), reason=reason)
        return True
    except (discord.Forbidden, discord.HTTPException):
        return False


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    ensure_guild(message.guild.id)
    settings = get_settings(message.guild.id)

    # Ignore moderators for automated moderation.
    if isinstance(message.author, discord.Member):
        bypass = (
            message.author.guild_permissions.manage_messages
            or message.author.guild_permissions.manage_guild
            or message.author.guild_permissions.administrator
        )
    else:
        bypass = False

    # Anti-link
    if settings["anti_links"] and not bypass and LINK_RE.search(message.content):
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

        embed = warning_embed(
            "🔗 Link Blocked",
            f"{message.author.mention}, links are currently restricted in this server.\n\n"
            "Use **#trusted-links** or ask a moderator for permission.",
        )
        try:
            warning_message = await message.channel.send(embed=embed, delete_after=7)
        except discord.HTTPException:
            warning_message = None

        log = warning_embed(
            "🔗 Link Blocked",
            f"**User:** {message.author.mention}\n"
            f"**Channel:** {message.channel.mention}\n"
            f"**Content:** `Link content removed`\n"
            f"**At:** <t:{int(time.time())}:F>",
        )
        await send_log(message.guild, log)
        await bot.process_commands(message)
        return

    # Anti-spam
    if settings["anti_spam"] and not bypass:
        count, times = mark_spam(message.guild.id, message.author.id)
        window = settings["spam_window"]
        while times and time.monotonic() - times[0] > window:
            times.pop(0)

        if len(times) >= settings["spam_limit"]:
            now = time.monotonic()
            key = (message.guild.id, message.author.id)

            if now - anti_spam_cooldown[key] > 15:
                anti_spam_cooldown[key] = now

                try:
                    await message.delete()
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    pass

                if isinstance(message.author, discord.Member):
                    success_timeout = await auto_timeout(
                        message.author,
                        settings["timeout_minutes"],
                        "Guardian anti-spam protection",
                    )
                else:
                    success_timeout = False

                title = "🚨 Anti-spam Triggered"
                desc = (
                    f"**User:** {message.author.mention}\n"
                    f"**Channel:** {message.channel.mention}\n"
                    f"**Detected:** `{len(times)} messages / {window}s`\n"
                    f"**Action:** `{'Timeout' if success_timeout else 'Message removal only'}`"
                )
                log = warning_embed(title, desc)
                await send_log(message.guild, log)

    await bot.process_commands(message)


# -----------------------------
# Presence / startup
# -----------------------------

@bot.event
async def on_guild_join(guild: discord.Guild):
    ensure_guild(guild.id)
    embed = success(
        "👋 Guardian is online",
        f"Thanks for adding Guardian to **{guild.name}**.\n\n"
        "Run `/help` to get started.",
    )
    # Choose a writable system/general channel.
    channel = guild.system_channel
    if channel is None:
        for candidate in guild.text_channels:
            if candidate.permissions_for(guild.me).send_messages:
                channel = candidate
                break
    if channel:
        try:
            await channel.send(embed=embed)
        except discord.HTTPException:
            pass


@bot.event
async def on_ready():
    init_db()
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} application commands.")
    except Exception as exc:
        print(f"Command sync error: {exc}")

    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="your server security",
        )
    )
    print(f"Logged in as {bot.user} ({bot.user.id})")
    print(f"Dashboard: {DASHBOARD_URL}")


# -----------------------------
# Flask dashboard
# -----------------------------

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = FLASK_SECRET_KEY


def dashboard_oauth_url():
    redirect_uri = f"{DASHBOARD_URL}/callback"
    scope = "identify guilds"
    return (
        "https://discord.com/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        "&response_type=code"
        f"&redirect_uri={requests.utils.quote(redirect_uri, safe='')}"
        f"&scope={requests.utils.quote(scope)}"
    )


def oauth_token(code):
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{DASHBOARD_URL}/callback",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(
        "https://discord.com/api/oauth2/token",
        data=data,
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def discord_api(endpoint, token):
    response = requests.get(
        f"https://discord.com/api/v10{endpoint}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def managed_guilds():
    if "oauth_token" not in session:
        return []

    user_guilds = discord_api("/users/@me/guilds", session["oauth_token"])
    bot_guild_ids = {str(guild.id) for guild in bot.guilds}

    result = []
    ADMIN = 0x8

    for guild in user_guilds:
        perms = int(guild.get("permissions", 0))
        owner = bool(guild.get("owner"))
        if owner or (perms & ADMIN) == ADMIN:
            guild["bot_present"] = str(guild["id"]) in bot_guild_ids
            result.append(guild)

    return result


def selected_guild(guild_id):
    for guild in managed_guilds():
        if str(guild["id"]) == str(guild_id):
            return guild
    return None


@app.route("/")
def index():
    if "oauth_token" not in session:
        return render_template("index.html", user=None, guilds=[])

    try:
        user = discord_api("/users/@me", session["oauth_token"])
        guilds = managed_guilds()
    except Exception:
        session.clear()
        return redirect(url_for("index"))

    return render_template("index.html", user=user, guilds=guilds)


@app.route("/login")
def login():
    return redirect(dashboard_oauth_url())


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return redirect(url_for("index"))

    try:
        token_data = oauth_token(code)
        session["oauth_token"] = token_data["access_token"]
        session["token_type"] = token_data.get("token_type", "Bearer")
    except Exception as exc:
        return render_template(
            "error.html",
            title="Authentication failed",
            message=f"Discord OAuth2 could not be completed. {exc}",
        )

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/server/<int:guild_id>", methods=["GET", "POST"])
def server_dashboard(guild_id: int):
    if "oauth_token" not in session:
        return redirect(url_for("login"))

    guild = selected_guild(guild_id)
    if not guild:
        return render_template(
            "error.html",
            title="Access denied",
            message="You need Administrator-level access to manage this server.",
        )

    if not guild["bot_present"]:
        return render_template(
            "error.html",
            title="Guardian not installed",
            message="Guardian is not in this server yet.",
        )

    if request.method == "POST":
        form = request.form

        update_settings(
            guild_id,
            anti_spam=1 if form.get("anti_spam") == "on" else 0,
            anti_links=1 if form.get("anti_links") == "on" else 0,
            lockdown=1 if form.get("lockdown") == "on" else 0,
            spam_limit=max(3, min(20, int(form.get("spam_limit", 6)))),
            spam_window=max(3, min(30, int(form.get("spam_window", 8)))),
            timeout_minutes=max(1, min(60, int(form.get("timeout_minutes", 10)))),
        )

        log_channel_raw = form.get("log_channel_id", "")
        log_channel_id = int(log_channel_raw) if log_channel_raw.isdigit() else None
        update_settings(guild_id, log_channel_id=log_channel_id)

        return redirect(url_for("server_dashboard", guild_id=guild_id, saved=1))

    settings = get_settings(guild_id)
    discord_guild = bot.get_guild(guild_id)

    channels = []
    if discord_guild:
        channels = [
            c for c in discord_guild.text_channels
            if c.permissions_for(discord_guild.me).send_messages
        ]

    return render_template(
        "server.html",
        user=discord_api("/users/@me", session["oauth_token"]),
        guild=guild,
        settings=settings,
        channels=channels,
        saved=request.args.get("saved") == "1",
    )


def start_flask():
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


def main():
    init_db()

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    bot.run(TOKEN)


if __name__ == "__main__":
    main()
