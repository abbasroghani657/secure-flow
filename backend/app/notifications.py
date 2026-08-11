"""Email alerts for scan results.

If SMTP is configured (``SMTP_HOST`` set), alerts are emailed; otherwise they are
logged. Sending never raises into the caller — a failed alert must not fail a scan.
"""

from __future__ import annotations

import json
import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.error import URLError
from urllib.request import Request, urlopen

from .config import settings
from .models import Integration, Scan
from .email_templates import get_base_html

logger = logging.getLogger("pentrixa.notifications")


def _summary_line(scan: Scan) -> str:
    return (
        f"Score {scan.security_score}/100 · "
        f"{scan.critical_count} critical, {scan.high_count} high, "
        f"{scan.medium_count} medium, {scan.low_count} low"
    )


def should_alert(scan: Scan) -> bool:
    """Alert when the scan surfaced something worth a human's attention."""
    if not settings.alerts_enabled:
        return False
    return (scan.critical_count + scan.high_count) > 0 or scan.new_findings_count > 0


def build_alert(scan: Scan, to_email: str) -> EmailMessage:
    link = f"{settings.app_base_url}/scans/{scan.id}"
    subject_bits = []
    if scan.new_findings_count > 0:
        subject_bits.append(f"{scan.new_findings_count} new")
    if scan.critical_count + scan.high_count > 0:
        subject_bits.append(f"{scan.critical_count + scan.high_count} high/critical")
    prefix = " (" + ", ".join(subject_bits) + ")" if subject_bits else ""

    body = (
        f"Pentrixa scan completed for {scan.target_url}{prefix}.\n\n"
        f"{_summary_line(scan)}\n"
    )
    if scan.new_findings_count > 0:
        body += f"\n{scan.new_findings_count} issue(s) are NEW since the previous scan.\n"
    body += f"\nView the full report:\n{link}\n\n— Pentrixa"

    msg = EmailMessage()
    msg["Subject"] = f"[Pentrixa] {scan.target_url}{prefix}"
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(body)
    
    html_body = f"<p>Pentrixa scan completed for <strong>{scan.target_url}</strong>{prefix}.</p>"
    html_body += f"<p><strong>{_summary_line(scan)}</strong></p>"
    if scan.new_findings_count > 0:
        html_body += f"<p style='color: #ef4444;'>{scan.new_findings_count} issue(s) are NEW since the previous scan.</p>"
    
    msg.add_alternative(get_base_html("Scan Completed", html_body, link, "View Full Report"), subtype="html")
    
    return msg


def send_scan_alert(scan: Scan, to_email: str) -> bool:
    """Send (or log) the alert. Returns True if an email was actually sent."""
    if not should_alert(scan):
        return False
    msg = build_alert(scan, to_email)

    if not settings.smtp_host:
        logger.info("ALERT (no SMTP configured) -> %s | %s", to_email, msg["Subject"])
        logger.info("ALERT body:\n%s", msg.get_content())
        return False

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_starttls:
                server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        logger.info("Alert emailed to %s for scan %s", to_email, scan.id)
        return True
    except Exception as exc:  # never let a mail failure break a scan
        return False


def _send_system_email(to_email: str, subject: str, body: str, html_content: str = None) -> bool:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(body)
    if html_content:
        msg.add_alternative(html_content, subtype="html")

    if not settings.smtp_host:
        logger.info("SYSTEM EMAIL (no SMTP) -> %s | %s", to_email, subject)
        logger.info("SYSTEM EMAIL body:\n%s", msg.get_content())
        return False

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_starttls:
                server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        logger.info("System email sent to %s: %s", to_email, subject)
        return True
    except Exception as exc:
        logger.warning("Failed to send system email: %s", exc)
        return False


def send_verification_email(email: str, token: str) -> bool:
    link = f"{settings.app_base_url}/verify-email?token={token}"
    body = (
        f"Welcome to {settings.app_name}!\n\n"
        f"Please verify your email address by clicking the link below:\n"
        f"{link}\n\n"
        f"If you did not create this account, you can safely ignore this email.\n"
    )
    html = get_base_html(
        "Verify your email", 
        f"<p>Welcome to {settings.app_name}!</p><p>Please verify your email address to get started.</p>",
        link,
        "Verify Email"
    )
    return _send_system_email(email, f"Verify your email for {settings.app_name}", body, html)


def send_password_reset_email(email: str, token: str) -> bool:
    link = f"{settings.app_base_url}/reset-password?token={token}"
    body = (
        f"We received a request to reset your password for {settings.app_name}.\n\n"
        f"Click the link below to set a new password:\n"
        f"{link}\n\n"
        f"This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.\n"
    )
    html = get_base_html(
        "Reset your password",
        "<p>We received a request to reset your password.</p><p>This link will expire in 1 hour.</p>",
        link,
        "Reset Password"
    )
    return _send_system_email(email, f"Password Reset Request", body, html)


def send_password_changed_notice(email: str, freeze_token: str) -> bool:
    freeze_link = f"{settings.app_base_url}/freeze-account?token={freeze_token}"
    body = (
        f"Your {settings.app_name} password was just changed.\n\n"
        f"If this was you, no further action is needed.\n\n"
        f"IF THIS WAS NOT YOU: Someone has compromised your account. Click the link below immediately to freeze your account and lock them out:\n"
        f"{freeze_link}\n"
    )
    html = get_base_html(
        "Security Alert: Password Changed",
        f"<p>Your {settings.app_name} password was just changed.</p><p>If this was you, no further action is needed.</p><p style='color: #ef4444; font-weight: bold;'>IF THIS WAS NOT YOU: Someone has compromised your account. Click the button below immediately to freeze your account.</p>",
        freeze_link,
        "FREEZE ACCOUNT"
    )
    return _send_system_email(email, "Security Alert: Password Changed", body, html)


# --------------------------------------------------------------------------- #
# Outbound integrations (Slack / Teams / Discord / generic webhook)
# --------------------------------------------------------------------------- #

def _integration_should_fire(integ: Integration, scan: Scan) -> bool:
    if not integ.enabled or not integ.target:
        return False
    if integ.events == "all":
        return True
    if integ.events == "new_only":
        return scan.new_findings_count > 0
    # default: critical_high
    return (scan.critical_count + scan.high_count) > 0 or scan.new_findings_count > 0


def _payload_for(kind: str, scan: Scan) -> dict:
    link = f"{settings.app_base_url}/scans/{scan.id}"
    headline = f"Pentrixa scan finished for {scan.target_url}"
    detail = _summary_line(scan)
    if scan.new_findings_count > 0:
        detail += f" · {scan.new_findings_count} new"
    text = f"*{headline}*\n{detail}\n<{link}|View report>"

    if kind == "slack":
        return {"text": f"{headline}\n{detail}\n{link}",
                "blocks": [
                    {"type": "section",
                     "text": {"type": "mrkdwn", "text": text}},
                ]}
    if kind == "discord":
        return {"content": f"**{headline}**\n{detail}\n{link}"}
    if kind == "teams":
        return {"@type": "MessageCard", "@context": "http://schema.org/extensions",
                "summary": headline, "title": headline,
                "text": f"{detail}\n\n[View report]({link})"}
    # generic webhook: structured JSON
    return {
        "event": "scan.completed",
        "target": scan.target_url,
        "scan_id": scan.id,
        "security_score": scan.security_score,
        "counts": {
            "critical": scan.critical_count, "high": scan.high_count,
            "medium": scan.medium_count, "low": scan.low_count,
            "new": scan.new_findings_count,
        },
        "report_url": link,
    }


def _post_json(url: str, payload: dict) -> bool:
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:  # noqa: S310 (user-supplied webhook URL)
            return 200 <= resp.status < 300
    except URLError as exc:
        logger.warning("integration POST failed: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("integration POST error: %s", exc)
        return False


def send_scan_integrations(scan: Scan, integrations: list[Integration], session=None) -> int:
    """Fire every matching integration for a completed scan. Returns count sent."""
    if not settings.alerts_enabled:
        return 0
    sent = 0
    for integ in integrations:
        if not _integration_should_fire(integ, scan):
            continue
        if _post_json(integ.target, _payload_for(integ.kind, scan)):
            sent += 1
            integ.last_fired_at = datetime.now(timezone.utc)
            if session is not None:
                session.add(integ)
    if sent and session is not None:
        session.commit()
    return sent


def test_integration(kind: str, target: str) -> bool:
    """Send a one-off 'connected' ping so the user can verify a channel."""
    link = settings.app_base_url
    msg = "Pentrixa is connected. You'll get scan alerts here."
    if kind == "slack":
        payload = {"text": f"✅ {msg}\n{link}"}
    elif kind == "discord":
        payload = {"content": f"✅ {msg}\n{link}"}
    elif kind == "teams":
        payload = {"@type": "MessageCard", "@context": "http://schema.org/extensions",
                   "summary": "Pentrixa connected", "title": "Pentrixa connected", "text": msg}
    else:
        payload = {"event": "test", "message": msg}
    return _post_json(target, payload)
