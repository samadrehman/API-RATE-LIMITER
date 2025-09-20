API Rate Limiter

A backend project that simulates a real-world API Rate Limiter.
It restricts how many API calls a user can make in a given time window and stores all requests in a database for monitoring, analytics, and admin controls.

This is the kind of service companies use to:

Prevent API abuse (spamming, DDOS)

Track request usage per user

Enforce fair usage policies

📌 Features

✅ Rate limiting – Restricts API calls per key

✅ Database persistence – Tracks users & requests in SQLite

✅ Admin dashboard (API) – View all API keys & usage

✅ Logs – Monitor the last requests with timestamps

✅ Extensible – Could be plugged into any company’s API gateway

🏗️ Tech Stack

Python 3.13

Flask (API framework)

SQLite (lightweight DB for persistence)



