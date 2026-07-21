"""Email alerts for scan results.

If SMTP is configured (``SMTP_HOST`` set), alerts are emailed; otherwise they are
logged. Sending never raises into the caller — a failed alert must not fail a scan.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from .config import settings
from .models import Scan

logger = logging.getLogger("secureflow.notifications")


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
        f"SecureFlow scan completed for {scan.target_url}{prefix}.\n\n"
        f"{_summary_line(scan)}\n"
    )
    if scan.new_findings_count > 0:
        body += f"\n{scan.new_findings_count} issue(s) are NEW since the previous scan.\n"
    body += f"\nView the full report:\n{link}\n\n— SecureFlow"

    msg = EmailMessage()
    msg["Subject"] = f"[SecureFlow] {scan.target_url}{prefix}"
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(body)
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
        logger.warning("Failed to send alert email: %s", exc)
        return False
