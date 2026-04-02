"""
SUNGLASSES Mailer — Send daily reports to users via email.

Uses Resend.com free tier (100 emails/day).
User sets their email once: sunglasses config --email user@example.com
Reports send automatically or on demand: sunglasses report --send
"""

import json
from pathlib import Path
from typing import Optional

try:
    import resend
    HAS_RESEND = True
except ImportError:
    HAS_RESEND = False

# Resend API key — SUNGLASSES project
# Free tier: 100 emails/day, 3000/month
# This key can only send emails FROM our verified domain
RESEND_API_KEY = ""  # Set after domain verification on resend.com

CONFIG_PATH = Path.home() / ".sunglasses" / "config.json"


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def _save_config(config: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def set_email(email: str, subscribe: bool = False):
    """Save user's email for daily reports."""
    config = _load_config()
    config["email"] = email
    config["subscribe"] = subscribe
    _save_config(config)
    return True


def get_email() -> Optional[str]:
    """Get saved email."""
    config = _load_config()
    return config.get("email")


def send_report(html_content: str, email: Optional[str] = None, date: str = "") -> bool:
    """Send HTML report via email."""
    if not HAS_RESEND:
        print("  Email sending requires: pip install resend")
        return False

    if not RESEND_API_KEY:
        print("  Email service not yet configured. Coming in v0.2!")
        print("  For now: sunglasses report --html --save report.html")
        return False

    email = email or get_email()
    if not email:
        print("  No email configured. Run: sunglasses config --email your@email.com")
        return False

    resend.api_key = RESEND_API_KEY

    try:
        resend.Emails.send({
            "from": "SUNGLASSES <reports@sunglasses.dev>",
            "to": [email],
            "subject": f"SUNGLASSES Threat Report — {date or 'Today'}",
            "html": html_content,
        })
        return True
    except Exception as e:
        print(f"  Email failed: {e}")
        return False
