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
import requests
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-this-secret")

CODESPACE_NAME = os.getenv("CODESPACE_NAME")
CODESPACE_DOMAIN = os.getenv(
    "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN",
    "app.github.dev",
)

DEFAULT_DASHBOARD_URL = (
    f"https://{CODESPACE_NAME}-5000.{CODESPACE_DOMAIN}"
    if CODESPACE_NAME
    else "http://127.0.0.1:5000"
)

DASHBOARD_URL = os.getenv(
    "DASHBOARD_URL",
    DEFAULT_DASHBOARD_URL,
).rstrip("/")


if not TOKEN:
    raise RuntimeError(
        "DISCORD_TOKEN is missing from .env"
    )

if not CLIENT_ID:
    raise RuntimeError(
        "DISCORD_CLIENT_ID is missing from .env"
    )

if not CLIENT_SECRET:
    raise RuntimeError(
        "DISCORD_CLIENT_SECRET is missing from .env"
    )


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "guardian.db"


# =========================================================
# DISCORD BOT
# =========================================================

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(
    command_prefix="!",
    intents=intents,
    help_command=None,
    case_insensitive=True,
)


# =========================================================
# FLASK
# =========================================================

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.secret_key = FLASK_SECRET_KEY


# =========================================================
# DATABASE
# =========================================================

db_lock = threading.Lock()


def get_db():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():
    with db_lock:
        connection = get_db()

        connection.executescript(
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

            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                details TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

        connection.commit()
        connection.close()


DEFAULT_SECURITY = {
    "anti_spam": 1,
    "anti_links": 1,
    "spam_limit": 6,
    "spam_window": 8,
    "timeout_minutes": 10,
    "lockdown": 0,
}


def ensure_guild(guild_id: int):
    with db_lock:
        connection = get_db()

        connection.execute(
            """
            INSERT OR IGNORE INTO guild_settings
            (
                guild_id,
                anti_spam,
                anti_links,
                spam_limit,
                spam_window,
                timeout_minutes,
                lockdown
            )
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

        connection.commit()
        connection.close()


def get_settings(guild_id: int):
    ensure_guild(guild_id)

    with db_lock:
        connection = get_db()

        row = connection.execute(
            """
            SELECT *
            FROM guild_settings
            WHERE guild_id = ?
            """,
            (guild_id,),
        ).fetchone()

        connection.close()

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

    values = {
        key: value
        for key, value in values.items()
        if key in allowed
    }

    if not values:
        return

    columns = ", ".join(
        f"{key} = ?"
        for key in values
    )

    parameters = list(values.values())
    parameters.append(guild_id)

    with db_lock:
        connection = get_db()

        connection.execute(
            f"""
            UPDATE guild_settings
            SET {columns}
            WHERE guild_id = ?
            """,
            parameters,
        )

        connection.commit()
        connection.close()


# =========================================================
# WARNING SYSTEM
# =========================================================

def add_warning(
    guild_id: int,
    user_id: int,
    moderator_id: int,
    reason: str,
):
    created_at = int(time.time())

    with db_lock:
        connection = get_db()

        cursor = connection.execute(
            """
            INSERT INTO warnings
            (
                guild_id,
                user_id,
                moderator_id,
                reason,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                guild_id,
                user_id,
                moderator_id,
                reason,
                created_at,
            ),
        )

        connection.commit()

        warning_id = cursor.lastrowid

        connection.close()

    return warning_id


def get_warnings(
    guild_id: int,
    user_id: int,
):
    with db_lock:
        connection = get_db()

        rows = connection.execute(
            """
            SELECT *
            FROM warnings
            WHERE guild_id = ?
            AND user_id = ?
            ORDER BY id DESC
            """,
            (
                guild_id,
                user_id,
            ),
        ).fetchall()

        connection.close()

    return [dict(row) for row in rows]


def clear_warnings(
    guild_id: int,
    user_id: int,
):
    with db_lock:
        connection = get_db()

        cursor = connection.execute(
            """
            DELETE FROM warnings
            WHERE guild_id = ?
            AND user_id = ?
            """,
            (
                guild_id,
                user_id,
            ),
        )

        connection.commit()

        count = cursor.rowcount

        connection.close()

    return count


# =========================================================
# SECURITY LOGS
# =========================================================

def add_security_log(
    guild_id: int,
    event_type: str,
    details: str,
    user_id: int | None = None,
):
    created_at = int(time.time())

    with db_lock:
        connection = get_db()

        connection.execute(
            """
            INSERT INTO security_logs
            (
                guild_id,
                event_type,
                user_id,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                guild_id,
                event_type,
                user_id,
                details,
                created_at,
            ),
        )

        connection.commit()
        connection.close()


def get_security_logs(
    guild_id: int,
    limit: int = 50,
):
    with db_lock:
        connection = get_db()

        rows = connection.execute(
            """
            SELECT *
            FROM security_logs
            WHERE guild_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (
                guild_id,
                limit,
            ),
        ).fetchall()

        connection.close()

    return [dict(row) for row in rows]


# =========================================================
# DISCORD EMBEDS
# =========================================================

def guardian_embed(
    title: str,
    description: str = "",
    color: discord.Color | None = None,
):
    embed = discord.Embed(
        title=title,
        description=description,
        color=color or discord.Color.from_rgb(
            150,
            150,
            155,
        ),
        timestamp=discord.utils.utcnow(),
    )

    embed.set_footer(
        text="Guardian • Security first"
    )

    return embed


def success_embed(title, description):
    return guardian_embed(
        title,
        description,
        discord.Color.from_rgb(
            100,
            190,
            145,
        ),
    )


def error_embed(title, description):
    return guardian_embed(
        title,
        description,
        discord.Color.from_rgb(
            210,
            90,
            90,
        ),
    )


def warning_embed(title, description):
    return guardian_embed(
        title,
        description,
        discord.Color.from_rgb(
            200,
            165,
            90,
        ),
    )


def info_embed(title, description):
    return guardian_embed(
        title,
        description,
        discord.Color.from_rgb(
            145,
            155,
            170,
        ),
    )


async def send_ephemeral(
    interaction: discord.Interaction,
    embed: discord.Embed,
):
    if interaction.response.is_done():
        await interaction.followup.send(
            embed=embed,
            ephemeral=True,
        )
    else:
        await interaction.response.send_message(
            embed=embed,
            ephemeral=True,
        )


# =========================================================
# MODERATION HELPERS
# =========================================================

def can_moderate(
    moderator: discord.Member,
    target: discord.Member,
):
    if target == moderator:
        return False

    if target == moderator.guild.owner:
        return False

    if moderator.guild.owner == moderator:
        return True

    if target == moderator.guild.me:
        return False

    return moderator.top_role > target.top_role


async def send_log(
    guild: discord.Guild,
    embed: discord.Embed,
):
    settings = get_settings(guild.id)

    channel_id = settings.get(
        "log_channel_id"
    )

    if not channel_id:
        return

    channel = guild.get_channel(
        channel_id
    )

    if not channel:
        return

    try:
        await channel.send(
            embed=embed
        )
    except discord.HTTPException:
        pass


# =========================================================
# HELP
# =========================================================

class HelpView(discord.ui.View):

    def __init__(self):
        super().__init__(timeout=180)

    @discord.ui.button(
        label="Moderation",
        style=discord.ButtonStyle.secondary,
    )
    async def moderation(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        embed = info_embed(
            "Moderation",
            "**Guardian moderation tools**\n\n"
            "`/ban` — Ban a member.\n"
            "`/unban` — Remove a ban.\n"
            "`/kick` — Kick a member.\n"
            "`/timeout` — Timeout a member.\n"
            "`/untimeout` — Remove a timeout.\n"
            "`/warn` — Add a warning.\n"
            "`/warnings` — View warnings.\n"
            "`/clearwarnings` — Clear warnings.\n"
            "`/clear` — Delete recent messages.",
        )

        await interaction.response.edit_message(
            embed=embed,
            view=self,
        )

    @discord.ui.button(
        label="Security",
        style=discord.ButtonStyle.secondary,
    )
    async def security(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        embed = info_embed(
            "Security",
            "**Automatic server protection**\n\n"
            "• Anti-Spam\n"
            "• Anti-Link\n"
            "• Automatic Timeout\n"
            "• Security Logs\n"
            "• Channel Lockdown\n\n"
            "`/security` — View protection status.\n"
            "`/setsecurity` — Configure protection.\n"
            "`/setlog` — Configure security logs.\n"
            "`/lock` — Lock a channel.\n"
            "`/unlock` — Unlock a channel.",
        )

        await interaction.response.edit_message(
            embed=embed,
            view=self,
        )

    @discord.ui.button(
        label="Close",
        style=discord.ButtonStyle.secondary,
    )
    async def close(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        await interaction.response.edit_message(
            view=None
        )


@bot.tree.command(
    name="help",
    description="Open Guardian's command guide.",
)
async def help_command(
    interaction: discord.Interaction,
):
    embed = guardian_embed(
        "Guardian",
        "**Security-first Discord protection.**\n\n"
        "Use the buttons below to browse Guardian's "
        "moderation and security systems.",
    )

    embed.add_field(
        name="Moderation",
        value=(
            "`/ban` ` /kick` ` /timeout` "
            "`/warn` ` /clear`"
        ),
        inline=False,
    )

    embed.add_field(
        name="Security",
        value=(
            "`/security` ` /setsecurity` "
            "`/setlog` ` /lock` ` /unlock`"
        ),
        inline=False,
    )

    await interaction.response.send_message(
        embed=embed,
        view=HelpView(),
        ephemeral=True,
    )


# =========================================================
# BASIC COMMANDS
# =========================================================

@bot.tree.command(
    name="ping",
    description="Check Guardian's latency.",
)
async def ping(
    interaction: discord.Interaction,
):
    latency = round(
        bot.latency * 1000
    )

    embed = success_embed(
        "Pong",
        f"WebSocket latency: **{latency}ms**",
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True,
    )


@bot.tree.command(
    name="serverinfo",
    description="Show server information.",
)
async def serverinfo(
    interaction: discord.Interaction,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used inside a server.",
            ),
        )

    guild = interaction.guild

    embed = info_embed(
        "Server Information",
        f"### {guild.name}",
    )

    if guild.icon:
        embed.set_thumbnail(
            url=guild.icon.url
        )

    embed.add_field(
        name="Members",
        value=f"`{guild.member_count:,}`",
        inline=True,
    )

    embed.add_field(
        name="Channels",
        value=f"`{len(guild.channels):,}`",
        inline=True,
    )

    embed.add_field(
        name="Roles",
        value=f"`{len(guild.roles):,}`",
        inline=True,
    )

    embed.add_field(
        name="Owner",
        value=f"<@{guild.owner_id}>",
        inline=True,
    )

    embed.add_field(
        name="Guild ID",
        value=f"`{guild.id}`",
        inline=True,
    )

    embed.add_field(
        name="Created",
        value=(
            f"<t:{int(guild.created_at.timestamp())}:F>"
        ),
        inline=True,
    )

    await interaction.response.send_message(
        embed=embed
    )


@bot.tree.command(
    name="userinfo",
    description="Show member information.",
)
@app_commands.describe(
    member="The member to inspect.",
)
async def userinfo(
    interaction: discord.Interaction,
    member: discord.Member,
):
    embed = info_embed(
        "User Information",
        f"### {member.display_name}",
    )

    embed.set_thumbnail(
        url=member.display_avatar.url
    )

    embed.add_field(
        name="Mention",
        value=member.mention,
        inline=True,
    )

    embed.add_field(
        name="User ID",
        value=f"`{member.id}`",
        inline=True,
    )

    embed.add_field(
        name="Joined",
        value=(
            f"<t:{int(member.joined_at.timestamp())}:R>"
            if member.joined_at
            else "Unknown"
        ),
        inline=True,
    )

    roles = [
        role.mention
        for role in member.roles[1:]
    ]

    embed.add_field(
        name=f"Roles ({len(roles)})",
        value=(
            " ".join(roles[-15:])
            if roles
            else "`No roles`"
        ),
        inline=False,
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# BAN
# =========================================================

@bot.tree.command(
    name="ban",
    description="Ban a member.",
)
@app_commands.describe(
    member="Member to ban.",
    reason="Reason for the ban.",
)
@app_commands.default_permissions(
    ban_members=True
)
async def ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    if not isinstance(
        interaction.user,
        discord.Member,
    ):
        return

    if not can_moderate(
        interaction.user,
        member,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Action blocked",
                "You cannot moderate this member because of role hierarchy.",
            ),
        )

    try:
        await member.ban(
            reason=(
                f"{reason} • "
                f"Moderator: {interaction.user}"
            )
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot ban this member.",
            ),
        )

    embed = success_embed(
        "Member Banned",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )

    await interaction.response.send_message(
        embed=embed
    )

    await send_log(
        interaction.guild,
        embed,
    )

    add_security_log(
        interaction.guild.id,
        "BAN",
        f"{member} was banned. Reason: {reason}",
        member.id,
    )


# =========================================================
# KICK
# =========================================================

@bot.tree.command(
    name="kick",
    description="Kick a member.",
)
@app_commands.describe(
    member="Member to kick.",
    reason="Reason for the kick.",
)
@app_commands.default_permissions(
    kick_members=True
)
async def kick(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    if not isinstance(
        interaction.user,
        discord.Member,
    ):
        return

    if not can_moderate(
        interaction.user,
        member,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Action blocked",
                "You cannot moderate this member because of role hierarchy.",
            ),
        )

    try:
        await member.kick(
            reason=reason
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot kick this member.",
            ),
        )

    embed = success_embed(
        "Member Kicked",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )

    await interaction.response.send_message(
        embed=embed
    )

    await send_log(
        interaction.guild,
        embed,
    )


# =========================================================
# TIMEOUT
# =========================================================

@bot.tree.command(
    name="timeout",
    description="Timeout a member.",
)
@app_commands.describe(
    member="Member to timeout.",
    minutes="Timeout duration.",
    reason="Reason for the timeout.",
)
@app_commands.default_permissions(
    moderate_members=True
)
async def timeout_cmd(
    interaction: discord.Interaction,
    member: discord.Member,
    minutes: app_commands.Range[int, 1, 40320],
    reason: str = "No reason provided",
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    if not isinstance(
        interaction.user,
        discord.Member,
    ):
        return

    if not can_moderate(
        interaction.user,
        member,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Action blocked",
                "You cannot moderate this member because of role hierarchy.",
            ),
        )

    try:
        await member.timeout(
            timedelta(
                minutes=minutes
            ),
            reason=reason,
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot timeout this member.",
            ),
        )

    embed = success_embed(
        "Member Timed Out",
        f"**Member:** {member.mention}\n"
        f"**Duration:** `{minutes} minute(s)`\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )

    await interaction.response.send_message(
        embed=embed
    )

    await send_log(
        interaction.guild,
        embed,
    )


# =========================================================
# UNTIMEOUT
# =========================================================

@bot.tree.command(
    name="untimeout",
    description="Remove a member's timeout.",
)
@app_commands.describe(
    member="Member to restore.",
    reason="Reason.",
)
@app_commands.default_permissions(
    moderate_members=True
)
async def untimeout(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    if not isinstance(
        interaction.user,
        discord.Member,
    ):
        return

    if not can_moderate(
        interaction.user,
        member,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Action blocked",
                "You cannot moderate this member.",
            ),
        )

    try:
        await member.timeout(
            None,
            reason=reason,
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot remove this timeout.",
            ),
        )

    embed = success_embed(
        "Timeout Removed",
        f"**Member:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# WARNINGS
# =========================================================

@bot.tree.command(
    name="warn",
    description="Warn a member.",
)
@app_commands.describe(
    member="Member to warn.",
    reason="Reason.",
)
@app_commands.default_permissions(
    moderate_members=True
)
async def warn(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    if not isinstance(
        interaction.user,
        discord.Member,
    ):
        return

    if not can_moderate(
        interaction.user,
        member,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Action blocked",
                "You cannot warn this member.",
            ),
        )

    warning_id = add_warning(
        interaction.guild.id,
        member.id,
        interaction.user.id,
        reason,
    )

    total = len(
        get_warnings(
            interaction.guild.id,
            member.id,
        )
    )

    embed = warning_embed(
        "Warning Added",
        f"**Member:** {member.mention}\n"
        f"**Warning:** `#{warning_id}`\n"
        f"**Total:** `{total}`\n"
        f"**Reason:** {reason}\n"
        f"**Moderator:** {interaction.user.mention}",
    )

    await interaction.response.send_message(
        embed=embed
    )


@bot.tree.command(
    name="warnings",
    description="View a member's warnings.",
)
@app_commands.describe(
    member="Member to inspect.",
)
@app_commands.default_permissions(
    moderate_members=True
)
async def warnings(
    interaction: discord.Interaction,
    member: discord.Member,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    warning_list = get_warnings(
        interaction.guild.id,
        member.id,
    )

    if not warning_list:
        return await send_ephemeral(
            interaction,
            info_embed(
                "Warnings",
                f"{member.mention} has no warnings.",
            ),
        )

    lines = []

    for warning in warning_list[:10]:
        lines.append(
            f"**#{warning['id']}** • "
            f"<t:{warning['created_at']}:R>\n"
            f"> {warning['reason']}"
        )

    embed = warning_embed(
        f"Warnings • {member}",
        "\n\n".join(lines),
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True,
    )


@bot.tree.command(
    name="clearwarnings",
    description="Clear all warnings for a member.",
)
@app_commands.describe(
    member="Member whose warnings should be cleared.",
)
@app_commands.default_permissions(
    moderate_members=True
)
async def clearwarnings(
    interaction: discord.Interaction,
    member: discord.Member,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    count = clear_warnings(
        interaction.guild.id,
        member.id,
    )

    embed = success_embed(
        "Warnings Cleared",
        f"Removed **{count}** warning(s) from {member.mention}.",
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# CLEAR
# =========================================================

@bot.tree.command(
    name="clear",
    description="Delete recent messages.",
)
@app_commands.describe(
    amount="Number of messages to delete.",
)
@app_commands.default_permissions(
    manage_messages=True
)
async def clear(
    interaction: discord.Interaction,
    amount: app_commands.Range[int, 1, 100],
):
    if not isinstance(
        interaction.channel,
        discord.TextChannel,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command requires a text channel.",
            ),
        )

    await interaction.response.defer(
        ephemeral=True
    )

    try:
        deleted = await interaction.channel.purge(
            limit=amount
        )

    except discord.Forbidden:
        return await interaction.followup.send(
            embed=error_embed(
                "Permission error",
                "Guardian cannot delete messages here.",
            ),
            ephemeral=True,
        )

    embed = success_embed(
        "Messages Cleared",
        f"Deleted **{len(deleted)}** message(s).",
    )

    await interaction.followup.send(
        embed=embed,
        ephemeral=True,
    )


# =========================================================
# LOCK / UNLOCK
# =========================================================

async def set_channel_lock(
    channel: discord.TextChannel,
    locked: bool,
):
    everyone = channel.guild.default_role

    overwrite = channel.overwrites_for(
        everyone
    )

    overwrite.send_messages = (
        False if locked else None
    )

    await channel.set_permissions(
        everyone,
        overwrite=overwrite,
    )


@bot.tree.command(
    name="lock",
    description="Lock the current channel.",
)
@app_commands.default_permissions(
    manage_channels=True
)
async def lock(
    interaction: discord.Interaction,
):
    if not isinstance(
        interaction.channel,
        discord.TextChannel,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command requires a text channel.",
            ),
        )

    try:
        await set_channel_lock(
            interaction.channel,
            True,
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot lock this channel.",
            ),
        )

    embed = warning_embed(
        "Channel Locked",
        f"{interaction.channel.mention} is now locked.\n\n"
        "> New messages are temporarily disabled.",
    )

    await interaction.response.send_message(
        embed=embed
    )


@bot.tree.command(
    name="unlock",
    description="Unlock the current channel.",
)
@app_commands.default_permissions(
    manage_channels=True
)
async def unlock(
    interaction: discord.Interaction,
):
    if not isinstance(
        interaction.channel,
        discord.TextChannel,
    ):
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command requires a text channel.",
            ),
        )

    try:
        await set_channel_lock(
            interaction.channel,
            False,
        )

    except discord.Forbidden:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Permission error",
                "Guardian cannot unlock this channel.",
            ),
        )

    embed = success_embed(
        "Channel Unlocked",
        f"{interaction.channel.mention} is available again.",
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# SECURITY SETTINGS
# =========================================================

@bot.tree.command(
    name="security",
    description="View current security settings.",
)
async def security(
    interaction: discord.Interaction,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    settings = get_settings(
        interaction.guild.id
    )

    def status(value):
        return "ON" if value else "OFF"

    embed = info_embed(
        "Security Status",
        "### Guardian Protection\n"
        "> Current protection settings for this server.",
    )

    embed.add_field(
        name="Anti-Spam",
        value=f"`{status(settings['anti_spam'])}`",
        inline=True,
    )

    embed.add_field(
        name="Anti-Link",
        value=f"`{status(settings['anti_links'])}`",
        inline=True,
    )

    embed.add_field(
        name="Lockdown",
        value=f"`{status(settings['lockdown'])}`",
        inline=True,
    )

    embed.add_field(
        name="Spam Limit",
        value=f"`{settings['spam_limit']} messages`",
        inline=True,
    )

    embed.add_field(
        name="Spam Window",
        value=f"`{settings['spam_window']} seconds`",
        inline=True,
    )

    embed.add_field(
        name="Auto Timeout",
        value=f"`{settings['timeout_minutes']} minutes`",
        inline=True,
    )

    await interaction.response.send_message(
        embed=embed
    )


@bot.tree.command(
    name="setsecurity",
    description="Configure Guardian security.",
)
@app_commands.describe(
    anti_spam="Enable or disable anti-spam.",
    anti_links="Enable or disable anti-link.",
    spam_limit="Messages allowed in the spam window.",
    spam_window="Spam detection window in seconds.",
    timeout_minutes="Automatic timeout duration.",
)
@app_commands.default_permissions(
    manage_guild=True
)
async def setsecurity(
    interaction: discord.Interaction,
    anti_spam: bool | None = None,
    anti_links: bool | None = None,
    spam_limit: app_commands.Range[int, 2, 20] | None = None,
    spam_window: app_commands.Range[int, 2, 30] | None = None,
    timeout_minutes: app_commands.Range[int, 1, 1440] | None = None,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    values = {}

    if anti_spam is not None:
        values["anti_spam"] = int(
            anti_spam
        )

    if anti_links is not None:
        values["anti_links"] = int(
            anti_links
        )

    if spam_limit is not None:
        values["spam_limit"] = int(
            spam_limit
        )

    if spam_window is not None:
        values["spam_window"] = int(
            spam_window
        )

    if timeout_minutes is not None:
        values["timeout_minutes"] = int(
            timeout_minutes
        )

    if not values:
        return await send_ephemeral(
            interaction,
            info_embed(
                "No changes",
                "No security values were provided.",
            ),
        )

    update_settings(
        interaction.guild.id,
        **values,
    )

    embed = success_embed(
        "Security Updated",
        "**Guardian security settings have been updated.**",
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# LOG CHANNEL
# =========================================================

@bot.tree.command(
    name="setlog",
    description="Set the security log channel.",
)
@app_commands.describe(
    channel="Channel where Guardian should send logs.",
)
@app_commands.default_permissions(
    manage_guild=True
)
async def setlog(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
):
    if not interaction.guild:
        return await send_ephemeral(
            interaction,
            error_embed(
                "Unavailable",
                "This command can only be used in a server.",
            ),
        )

    update_settings(
        interaction.guild.id,
        log_channel_id=channel.id,
    )

    embed = success_embed(
        "Log Channel Updated",
        f"Security events will now be sent to {channel.mention}.",
    )

    await interaction.response.send_message(
        embed=embed
    )


# =========================================================
# ANTI-SPAM
# =========================================================

spam_cache = defaultdict(
    lambda: defaultdict(
        lambda: deque(
            maxlen=30
        )
    )
)

spam_cooldown = defaultdict(
    float
)


LINK_RE = re.compile(
    r"(https?://\S+|www\.\S+|discord\.gg/\S+|discord(?:app)?\.com/invite/\S+)",
    re.IGNORECASE,
)


@bot.event
async def on_message(
    message: discord.Message,
):
    if message.author.bot:
        return

    if not message.guild:
        await bot.process_commands(
            message
        )
        return

    settings = get_settings(
        message.guild.id
    )

    # -------------------------
    # Anti-Link
    # -------------------------

    if (
        settings["anti_links"]
        and LINK_RE.search(
            message.content
        )
    ):
        if (
            isinstance(
                message.author,
                discord.Member,
            )
            and not message.author.guild_permissions.manage_messages
        ):
            try:
                await message.delete()
            except discord.HTTPException:
                pass

            try:
                await message.channel.send(
                    f"{message.author.mention} "
                    "**link blocked.**",
                    delete_after=4,
                )
            except discord.HTTPException:
                pass

            add_security_log(
                message.guild.id,
                "ANTI_LINK",
                f"Blocked link from {message.author}",
                message.author.id,
            )

    # -------------------------
    # Anti-Spam
    # -------------------------

    if settings["anti_spam"]:
        now = time.monotonic()

        timestamps = spam_cache[
            message.guild.id
        ][message.author.id]

        timestamps.append(now)

        while timestamps and (
            now - timestamps[0]
            > settings["spam_window"]
        ):
            timestamps.popleft()

        if (
            len(timestamps)
            >= settings["spam_limit"]
        ):
            cooldown_key = (
                message.guild.id,
                message.author.id,
            )

            if (
                now
                - spam_cooldown[cooldown_key]
                > settings["spam_window"]
            ):
                spam_cooldown[
                    cooldown_key
                ] = now

                if isinstance(
                    message.author,
                    discord.Member,
                ):
                    if not message.author.guild_permissions.manage_messages:
                        try:
                            await message.author.timeout(
                                timedelta(
                                    minutes=settings[
                                        "timeout_minutes"
                                    ]
                                ),
                                reason="Guardian Anti-Spam",
                            )

                            embed = warning_embed(
                                "Anti-Spam Triggered",
                                f"{message.author.mention} "
                                f"was automatically timed out.\n\n"
                                f"**Duration:** "
                                f"`{settings['timeout_minutes']} minutes`",
                            )

                            await send_log(
                                message.guild,
                                embed,
                            )

                            add_security_log(
                                message.guild.id,
                                "ANTI_SPAM",
                                (
                                    f"{message.author} "
                                    f"was automatically timed out."
                                ),
                                message.author.id,
                            )

                        except discord.HTTPException:
                            pass

    await bot.process_commands(
        message
    )


# =========================================================
# DISCORD EVENTS
# =========================================================

@bot.event
async def on_ready():
    init_db()

    try:
        synced = await bot.tree.sync()

        print(
            f"[Guardian] Synced {len(synced)} slash command(s)."
        )

    except Exception as error:
        print(
            f"[Guardian] Slash command sync failed: {error}"
        )

    print(
        f"[Guardian] Logged in as {bot.user}"
    )

    print(
        f"[Guardian] Dashboard: {DASHBOARD_URL}"
    )


@bot.event
async def on_guild_join(
    guild: discord.Guild,
):
    ensure_guild(
        guild.id
    )


# =========================================================
# WEB HELPERS
# =========================================================

def oauth_redirect_uri():
    return (
        f"{DASHBOARD_URL}/callback"
    )


def discord_oauth_url():
    return (
        "https://discord.com/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        "&response_type=code"
        f"&redirect_uri={oauth_redirect_uri()}"
        "&scope=identify%20guilds"
    )


def get_current_user():
    return session.get(
        "user"
    )


def get_user_guilds():
    return session.get(
        "guilds",
        [],
    )


def can_manage_guild(
    guild_data,
):
    permissions = int(
        guild_data.get(
            "permissions",
            0,
        )
    )

    administrator = (
        permissions & 0x8
    )

    manage_guild = (
        permissions & 0x20
    )

    return bool(
        administrator
        or manage_guild
    )


def get_managed_guilds():
    managed = []

    bot_guild_ids = {
        guild.id
        for guild in bot.guilds
    }

    for guild_data in get_user_guilds():
        try:
            guild_id = int(
                guild_data["id"]
            )
        except (
            KeyError,
            ValueError,
            TypeError,
        ):
            continue

        if (
            guild_id in bot_guild_ids
            and can_manage_guild(
                guild_data
            )
        ):
            managed.append(
                guild_data
            )

    return managed


def find_guild(
    guild_id: int,
):
    for guild in get_managed_guilds():
        if int(
            guild["id"]
        ) == guild_id:
            return guild

    return None


# =========================================================
# WEB ROUTES
# =========================================================

@app.route("/")
def index():
    return render_template(
        "index.html",
        user=get_current_user(),
    )


@app.route("/login")
def login():
    return redirect(
        discord_oauth_url()
    )


@app.route("/callback")
def callback():
    code = request.args.get(
        "code"
    )

    if not code:
        return render_template(
            "error.html",
            message="Missing OAuth2 authorization code.",
        ), 400

    token_response = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": oauth_redirect_uri(),
        },
        headers={
            "Content-Type": (
                "application/x-www-form-urlencoded"
            )
        },
        timeout=15,
    )

    if token_response.status_code != 200:
        return render_template(
            "error.html",
            message="Discord OAuth2 authorization failed.",
        ), 400

    token_data = token_response.json()

    access_token = token_data.get(
        "access_token"
    )

    if not access_token:
        return render_template(
            "error.html",
            message="Discord did not return an access token.",
        ), 400

    headers = {
        "Authorization": (
            f"Bearer {access_token}"
        )
    }

    user_response = requests.get(
        "https://discord.com/api/users/@me",
        headers=headers,
        timeout=15,
    )

    guild_response = requests.get(
        "https://discord.com/api/users/@me/guilds",
        headers=headers,
        timeout=15,
    )

    if (
        user_response.status_code != 200
        or guild_response.status_code != 200
    ):
        return render_template(
            "error.html",
            message="Unable to retrieve your Discord account.",
        ), 400

    session["user"] = (
        user_response.json()
    )

    session["guilds"] = (
        guild_response.json()
    )

    return redirect(
        url_for("dashboard")
    )


@app.route("/logout")
def logout():
    session.clear()

    return redirect(
        url_for("index")
    )


@app.route("/dashboard")
def dashboard():
    user = get_current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    guilds = get_managed_guilds()

    return render_template(
        "dashboard.html",
        user=user,
        guilds=guilds,
    )


@app.route("/server/<int:guild_id>")
def server_dashboard(
    guild_id: int,
):
    user = get_current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    guild_data = find_guild(
        guild_id
    )

    if not guild_data:
        return render_template(
            "error.html",
            message="You do not have access to this server.",
        ), 403

    guild = bot.get_guild(
        guild_id
    )

    if not guild:
        return render_template(
            "error.html",
            message="Guardian is not connected to this server.",
        ), 404

    settings = get_settings(
        guild_id
    )

    logs = get_security_logs(
        guild_id,
        30,
    )

    channels = [
        channel
        for channel in guild.text_channels
    ]

    return render_template(
        "server.html",
        user=user,
        guild=guild,
        guild_data=guild_data,
        settings=settings,
        logs=logs,
        channels=channels,
    )


@app.route(
    "/server/<int:guild_id>/settings",
    methods=["POST"],
)
def save_server_settings(
    guild_id: int,
):
    user = get_current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    guild_data = find_guild(
        guild_id
    )

    if not guild_data:
        return render_template(
            "error.html",
            message="You do not have access to this server.",
        ), 403

    anti_spam = (
        1
        if request.form.get(
            "anti_spam"
        )
        else 0
    )

    anti_links = (
        1
        if request.form.get(
            "anti_links"
        )
        else 0
    )

    try:
        spam_limit = max(
            2,
            min(
                20,
                int(
                    request.form.get(
                        "spam_limit",
                        6,
                    )
                ),
            ),
        )

        spam_window = max(
            2,
            min(
                30,
                int(
                    request.form.get(
                        "spam_window",
                        8,
                    )
                ),
            ),
        )

        timeout_minutes = max(
            1,
            min(
                1440,
                int(
                    request.form.get(
                        "timeout_minutes",
                        10,
                    )
                ),
            ),
        )

    except ValueError:
        return render_template(
            "error.html",
            message="Invalid security settings.",
        ), 400

    log_channel_id = request.form.get(
        "log_channel_id"
    )

    try:
        log_channel_id = (
            int(log_channel_id)
            if log_channel_id
            else None
        )
    except ValueError:
        log_channel_id = None

    update_settings(
        guild_id,
        anti_spam=anti_spam,
        anti_links=anti_links,
        spam_limit=spam_limit,
        spam_window=spam_window,
        timeout_minutes=timeout_minutes,
        log_channel_id=log_channel_id,
    )

    return redirect(
        url_for(
            "server_dashboard",
            guild_id=guild_id,
        )
    )


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "error.html",
        message="An internal server error occurred.",
    ), 500


# =========================================================
# FLASK THREAD
# =========================================================

def run_web():
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )


# =========================================================
# STARTUP
# =========================================================

async def start():
    init_db()

    web_thread = threading.Thread(
        target=run_web,
        daemon=True,
    )

    web_thread.start()

    await bot.start(
        TOKEN
    )


if __name__ == "__main__":
    try:
        asyncio.run(
            start()
        )

    except KeyboardInterrupt:
        print(
            "[Guardian] Shutdown requested."
        )
