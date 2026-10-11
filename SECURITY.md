# Security and responsible use

- Investigate only assets you own or are authorised to assess. The tool is passive: it queries public databases/APIs. It does not scan ports, exploit anything, submit URLs for scanning, or download files from targets.
- Private/loopback/reserved IPs and local domain names are refused.
- Provider keys live only in `.env` (server side). They are never sent to the browser, never written to reports, and are scrubbed from error text. HTTP client request logging is turned down so URLs with keys are not logged.
- Everything you search is sent to third-party services (RDAP, crt.sh, Shodan InternetDB, ipwho.is, urlscan.io, GitHub etc.; plus VirusTotal/AbuseIPDB/Shodan/OTX/OpenAI if you add keys). Do not search confidential or personal data you have no right to look up. If an OpenAI key is set, the collected findings and the target are sent to OpenAI to write the summary; untick "Use my API keys" to prevent this per search.
- `APP_API_KEY` is a single shared secret, not user login. The server binds to 127.0.0.1 by default.
- Results can be stale, incomplete or false-positive. The score is a heuristic.

## Before any public/production deployment (not done in this student project)
Per-user authentication and roles, HTTPS via a reverse proxy, rate limiting, audit logs, database migrations (Alembic), a durable job queue instead of in-process threads, secret manager, backups and retention policy, dependency scanning, and an independent security review.
