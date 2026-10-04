# Guardian

A polished Discord security and moderation bot with a dark web dashboard.

## Features

### Moderation
- `/ban`
- `/unban`
- `/kick`
- `/timeout`
- `/untimeout`
- `/warn`
- `/warnings`
- `/clearwarnings`
- `/clear`
- `/lock`
- `/unlock`

### Security
- Anti-spam
- Anti-link
- Automatic timeout after repeated spam
- Security settings per server
- Security event logging
- Lockdown mode
- Persistent SQLite database

### Utility
- `/help`
- `/ping`
- `/serverinfo`
- `/userinfo`

### Dashboard
- Discord OAuth2 login
- Server selector
- Security toggles
- Spam threshold settings
- Log channel selection
- Dark premium UI
- Mobile responsive layout

### Discord formatting showcase

The bot is intentionally designed around Discord's own text formatting:

**Bold**
*Italic*
__Underline__
~~Strikethrough~~
||Spoiler||
`inline code`

```py
print("Hello Discord")
```

> Quoted text

<https://example.com>

[Example](https://example.com)

<@123456789012345678>
<@&123456789012345678>
<#123456789012345678>
@everyone

<t:1728000000:F>
<t:1728000000:R>

## Setup

### 1. Install Python

Python 3.11+ is recommended.

### 2. Install packages

```bash
pip install -r requirements.txt
```

### 3. Create `.env`

Copy `.env.example` to `.env` and fill in your real values.

Never share your bot token.

### 4. Discord Developer Portal

Create an application and bot.

Enable:

- Server Members Intent
- Message Content Intent

Invite with OAuth2 scopes:

- `bot`
- `applications.commands`

Recommended permissions:

- View Channels
- Send Messages
- Embed Links
- Read Message History
- Manage Messages
- Kick Members
- Ban Members
- Moderate Members
- Manage Channels

### 5. Dashboard OAuth2

Add this redirect URI to the Discord Developer Portal:

```text
http://127.0.0.1:5000/callback
```

For production, use your HTTPS domain.

### 6. Start

```bash
python bot.py
```

The bot and dashboard start together.

Dashboard:
http://127.0.0.1:5000

## Production notes

For public production:
- Use HTTPS.
- Set a strong FLASK_SECRET_KEY.
- Use a managed database if the bot grows.
- Run behind a production WSGI server.
- Keep secrets outside source control.
- Review Discord permissions carefully.
