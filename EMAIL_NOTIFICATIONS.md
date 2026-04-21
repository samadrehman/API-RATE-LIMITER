# Email Notifications

This project can support email notifications for rate-limit and security events.

Current status:
- SMTP notification pipeline is implemented and enabled via environment variables.
- Sending is asynchronous and fail-safe (notification failures do not break API responses).

## Suggested Notification Events

- Rate limit reached (429 spikes)
- API key blocked/unblocked by admin
- Tier upgraded/downgraded
- Suspicious activity detected (abuse heuristics)
- Daily usage summary

## Recommended Environment Variables

- EMAIL_NOTIFICATIONS_ENABLED=true
- SMTP_HOST=smtp.example.com
- SMTP_PORT=587
- SMTP_USERNAME=your_smtp_username
- SMTP_PASSWORD=your_smtp_password
- SMTP_USE_TLS=true
- SMTP_USE_SSL=false
- EMAIL_FROM=noreply@example.com
- ALERT_EMAIL_TO=ops@example.com
- SMTP_TIMEOUT_SECONDS=8
- EMAIL_EVENT_COOLDOWN_SECONDS=300

## Suggested Trigger Points

- app.py
  - after key ban and 429 rate-limit responses
  - when admin block/unblock actions are executed
  - when admin upgrades tier
- log_manager.py
  - when suspicious activity or abuse events are logged

## Suggested Payload Contract

Event payload fields:
- event_type
- timestamp
- user_id (if available)
- api_key_prefix
- tier
- endpoint
- status_code
- message
- metadata

## Minimal Subject Templates

- [RateLimiter] Rate limit reached for key {api_key_prefix}
- [RateLimiter] API key blocked: {api_key_prefix}
- [RateLimiter] Tier changed to {tier} for {user_id}
- [RateLimiter] Suspicious activity detected from {ip_hash}

## Implementation Notes

- Send emails asynchronously to avoid blocking API response time.
- Add retry with exponential backoff for SMTP failures.
- Protect secrets and never log SMTP passwords.
- Add per-event cooldown to prevent alert spam.
- Keep GDPR/privacy in mind when including identifiers.

## Next Step (Optional)

Implemented module:

- email_notifier.py

Core function:

- send_notification(event_type: str, payload: dict, subject: str | None = None) -> bool

Integrated events:

- tier_changed
- api_key_blocked
- api_key_unblocked
- api_key_temporary_ban
- rate_limit_exceeded
- sdk_rate_limit_exceeded
- abuse_detected
