import os, sys, httpx, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi.testclient import TestClient

KEYS = ["APP_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "OTX_API_KEY", "URLSCAN_API_KEY", "OPENAI_API_KEY"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    from app.main import app
    with TestClient(app) as c:      # `with` runs startup/shutdown, so the scheduler really starts
        yield c


def resp(status=200, body=None, url="https://x"):
    return httpx.Response(status, json=body, request=httpx.Request("GET", url))


@pytest.fixture
def fake_net(monkeypatch):
    """Replace network calls with canned provider responses. Tests the parsing/handling code, NOT the real services."""
    from app import providers
    routes = {}

    def fake_get(url, headers=None, params=None, timeout=15):
        for needle, r in routes.items():
            if needle in url:
                if isinstance(r, Exception):
                    raise r
                return r(url) if callable(r) else r
        raise httpx.ConnectError("no route in test: " + url)

    monkeypatch.setattr(providers, "http_get", fake_get)
    monkeypatch.setattr(providers, "dns_lookup", lambda t, x: [providers.F("DNS", "A records", "93.184.216.34")])
    monkeypatch.setattr(providers, "reverse_dns", lambda t, x: [providers.F("DNS", "Reverse DNS (PTR)", "dns.google.")])
    return routes


def wait_done(client, iid):
    return client.get(f"/api/investigations/{iid}").json()   # TestClient finishes background tasks before returning
