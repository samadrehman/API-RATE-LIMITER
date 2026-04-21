"""
Email notification utility for operational and security events.

Designed to be fail-safe:
- Never raises exceptions to callers.
- Sends asynchronously in background threads.
- Supports cooldown to reduce duplicate alert spam.
"""

import json
import os
import smtplib
import threading
import time
from email.message import EmailMessage
from threading import Lock
from typing import Dict, Optional


class EmailNotifier:
    """Asynchronous SMTP notifier with per-event cooldown."""

    def __init__(
        self,
        enabled: bool,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        use_tls: bool,
        use_ssl: bool,
        sender: str,
        recipients: list[str],
        timeout_seconds: int,
        cooldown_seconds: int,
    ) -> None:
        self.enabled = enabled
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.sender = sender
        self.recipients = recipients
        self.timeout_seconds = timeout_seconds
        self.cooldown_seconds = cooldown_seconds

        self._cooldown_map: Dict[str, float] = {}
        self._lock = Lock()

    @classmethod
    def from_env(cls) -> "EmailNotifier":
        enabled = os.getenv("EMAIL_NOTIFICATIONS_ENABLED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
        use_ssl = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
        sender = os.getenv("EMAIL_FROM", "noreply@localhost")

        recipients_raw = os.getenv("ALERT_EMAIL_TO", "")
        recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

        timeout_seconds = int(os.getenv("SMTP_TIMEOUT_SECONDS", "8"))
        cooldown_seconds = int(os.getenv("EMAIL_EVENT_COOLDOWN_SECONDS", "300"))

        return cls(
            enabled=enabled,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            use_tls=use_tls,
            use_ssl=use_ssl,
            sender=sender,
            recipients=recipients,
            timeout_seconds=timeout_seconds,
            cooldown_seconds=cooldown_seconds,
        )

    def is_configured(self) -> bool:
        if not self.enabled:
            return False
        if not self.smtp_host or not self.recipients:
            return False
        return True

    def _cooldown_key(self, event_type: str, payload: Dict) -> str:
        # Keep cooldown key stable for repeated events from same source.
        source = payload.get("api_key_prefix") or payload.get("ip") or payload.get("ip_hash") or "global"
        return f"{event_type}:{source}"

    def _is_in_cooldown(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._cooldown_map.get(key, 0)
            if now - last < self.cooldown_seconds:
                return True
            self._cooldown_map[key] = now
            return False

    def send_notification(self, event_type: str, payload: Dict, subject: Optional[str] = None) -> bool:
        """Queue an email notification in a background thread."""
        if not self.is_configured():
            return False

        key = self._cooldown_key(event_type, payload)
        if self._is_in_cooldown(key):
            return False

        final_subject = subject or f"[RateLimiter] {event_type}"

        thread = threading.Thread(
            target=self._send_sync,
            args=(final_subject, event_type, payload),
            daemon=True,
        )
        thread.start()
        return True

    def _send_sync(self, subject: str, event_type: str, payload: Dict) -> None:
        try:
            message = EmailMessage()
            message["From"] = self.sender
            message["To"] = ", ".join(self.recipients)
            message["Subject"] = subject

            body = {
                "event_type": event_type,
                "timestamp": int(time.time()),
                "payload": payload,
            }
            message.set_content(json.dumps(body, indent=2, ensure_ascii=True))

            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=self.timeout_seconds)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout_seconds)

            with server:
                if not self.use_ssl and self.use_tls:
                    server.starttls()
                if self.smtp_username:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(message)
        except Exception as exc:
            print(f"Email notification failed: {type(exc).__name__}: {exc}")
