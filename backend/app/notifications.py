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
