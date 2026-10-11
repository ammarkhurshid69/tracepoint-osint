# Tracepoint: OSINT investigation desk (v2.0)

Search a **domain, IP, URL, e-mail, username or file hash**. Tracepoint detects the type, asks the public sources that apply, stores the result in SQLite, scores it, summarises it, can re-check it every 15 minutes (with alerts), and exports PDF/CSV.

Works **without any API key**. Keys only add more sources. There is **no simulated data**: every finding is labelled `live` (fetched from a named source), `system` (a note from this app) or `error` (a lookup failed).

## Run on Windows (copy-paste)

1. Install Python 3.10 or newer from python.org (tick **Add Python to PATH**).
2. Extract the ZIP. Open **PowerShell** in the extracted folder (the one containing `run_windows.bat`):

```powershell
cd C:\Users\ammar\Downloads\Tracepoint_v2.0
.\run_windows.bat
```

The browser opens at http://127.0.0.1:8000. Keep the window open. Stop with `Ctrl+C`.

Manual way (same result):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

> The earlier `No module named 'app'` error happens when PowerShell is in the wrong folder. Always `cd` into the folder that contains the `app` folder first.

Needs internet. Offline it still opens, but searches show "could not reach the service" errors instead of findings.

## What each search type checks

| You enter | Sources queried (no key) | Extra sources with your key |
|---|---|---|
| Domain | DNS (A/AAAA/MX/NS/TXT, SPF, DMARC), RDAP registration + domain age, certificate-transparency hostnames (crt.sh), urlscan.io existing scans | VirusTotal, AlienVault OTX |
| IP | RDAP network owner, GeoIP/ASN, reverse DNS, Shodan InternetDB (open ports, CVEs, tags), urlscan.io | AbuseIPDB, Shodan, VirusTotal, OTX |
| URL | DNS and RDAP of the host, urlscan.io | VirusTotal, OTX |
| E-mail | Syntax, MX, disposable-domain list, Gravatar, GitHub public e-mail, domain RDAP | none |
| Username | GitHub, GitLab, Keybase, Docker Hub, DEV, Hacker News public APIs | none |
| File hash | CIRCL known-file database | VirusTotal, OTX |

"Search anything" means anything that fits one of those six shapes. It cannot find private data, social-media posts, or breach data.

## Adding API keys (optional)

Edit `.env` (created from `.env.example`), save, restart the server. Keys are read only by the server.

| Variable | Where to get it (free tiers exist, with limits) |
|---|---|
| `VIRUSTOTAL_API_KEY` | virustotal.com, sign in, profile, API key |
| `ABUSEIPDB_API_KEY` | abuseipdb.com, account, API |
| `SHODAN_API_KEY` | account.shodan.io (host lookups may need a paid plan; InternetDB works free) |
| `OTX_API_KEY` | otx.alienvault.com, settings |
| `URLSCAN_API_KEY` | urlscan.io, profile (optional, raises limits) |
| `OPENAI_API_KEY` | platform.openai.com (optional written summary; sends findings to OpenAI) |

The **Sources** tab shows which are ready. "Key present" does not mean the key is valid; an invalid key shows up as a clear error on the finding.

## Other settings

`APP_API_KEY` protects all `/api` routes (the page shows an **API key** box). `MONITOR_INTERVAL_MINUTES` changes the re-check interval. Health: `/api/health`. Provider status: `/api/providers`. Interactive docs: `/docs`.

## Tests

```powershell
.\run_tests_windows.bat
```
or `python -m pip install -r requirements-dev.txt` then `python -m pytest -q`. Provider tests use canned responses, so they test this app's handling code, not the real services. `tests/e2e/` drives the real `app.js` in jsdom (needs Node: `cd tests\e2e; npm i; node run.js` with `python tests\e2e_server.py 8765` running).

## How it fits together (for your viva)

`app/detect.py` input validation and type detection, `app/providers.py` one function per source, `app/engine.py` runs providers in parallel threads, scores, summarises, diffs against the last run and raises alerts, `app/scheduler.py` APScheduler (one job `mon-<id>` per monitored case), `app/reports.py` CSV (formula-injection safe) and PDF, `app/main.py` routes, `app/static/` the UI.

**Why `[object Object]` happened (v1.2 class of bug):** FastAPI sends validation errors as an array of objects. JavaScript turns an object into text as `[object Object]`. v2.0 fixes it twice: the server always returns `detail` as a plain string, and `formatError()` in `app.js` converts any error shape into readable text.

## Limits

Student prototype. Scores are heuristics. Monitoring runs only while the server runs. Single shared API key, no user accounts, in-process job queue. See `SECURITY.md` for what production would need.
