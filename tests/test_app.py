import time, httpx, pytest
from conftest import resp, wait_done
from app import detect, engine, scheduler, db, reports, providers

RDAP = {"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]]}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}], "status": ["active"]}


# ---------- input detection / validation
@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", ("domain", "example.com")), ("8.8.8.8", ("ip", "8.8.8.8")), ("2001:4860:4860::8888", ("ip", "2001:4860:4860::8888")),
    ("https://a.com/x?y=1#f", ("url", "https://a.com/x?y=1")), ("Bob@Example.org", ("email", "bob@example.org")),
    ("d41d8cd98f00b204e9800998ecf8427e", ("hash", "d41d8cd98f00b204e9800998ecf8427e")), ("@octocat", ("username", "octocat")),
    ("sub.site.co.uk", ("domain", "sub.site.co.uk"))])
def test_detect_ok(raw, expected):
    assert detect.normalize(raw) == expected


@pytest.mark.parametrize("raw", ["192.168.1.1", "127.0.0.1", "http://localhost/x", "a.local", "http://u:p@a.com", "ftp://a.com",
                                 "api_key=abc", "bad host.com", "", "a" * 3000, "x\ny.com"])
def test_detect_rejects(raw):
    with pytest.raises(ValueError):
        detect.normalize(raw)


def test_forced_type_is_validated():
    with pytest.raises(ValueError):
        detect.normalize("example.com", "ip")


# ---------- API basics and the [object Object] root cause
def test_health_and_providers_never_leak_secrets(client, monkeypatch):
    assert client.get("/api/health").json()["status"] == "ok"
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "SUPERSECRETKEY123456")
    r = client.get("/api/providers")
    vt = next(p for p in r.json()["providers"] if p["id"] == "virustotal")
    assert vt["configured"] is True
    assert "SUPERSECRETKEY123456" not in r.text
    assert next(p for p in r.json()["providers"] if p["id"] == "dns")["configured"] is True


@pytest.mark.parametrize("payload", [{"target": ""}, {"target": "x", "target_type": "nonsense"}, {"target": "192.168.0.5"}, {}, {"target": "a.com", "monitoring": "maybe"}])
def test_every_error_detail_is_a_plain_string(client, payload):
    r = client.post("/api/investigations", json=payload)
    assert r.status_code == 422
    assert isinstance(r.json()["detail"], str) and r.json()["detail"]   # an array here is what produced "[object Object]"


def test_404s_are_strings(client):
    for path in ("/api/investigations/999", "/api/investigations/999/export.pdf"):
        r = client.get(path)
        assert r.status_code == 404 and isinstance(r.json()["detail"], str)


# ---------- investigations end to end (network mocked)
def test_domain_investigation_persists_and_scores(client, fake_net):
    fake_net["rdap.org/domain"] = resp(200, RDAP)
    fake_net["crt.sh"] = resp(200, [{"name_value": "example.com\nwww.example.com\n*.example.com"}, {"name_value": "mail.example.com"}])
    fake_net["urlscan.io"] = resp(200, {"results": [{"task": {"time": "2025-01-01T00:00:00Z"}, "page": {"url": "https://example.com"}, "_id": "abc"}]})
    r = client.post("/api/investigations", json={"target": "EXAMPLE.com"})
    assert r.status_code == 201 and r.json()["target"] == "example.com" and r.json()["target_type"] == "domain"
    d = wait_done(client, r.json()["id"])
    assert d["status"] == "completed" and d["progress"] == 100 and d["run_count"] == 1
    titles = [f["title"] for f in d["findings"]]
    assert "Domain registration (WHOIS successor)" in titles and any("3 hostnames" in t for t in titles)
    assert d["summary_source"] == "rule-based" and "not a validated rating" in d["summary"]
    assert any(f["provenance"] == "system" and "not queried" in f["title"] for f in d["findings"])   # keyed sources skipped transparently
    assert not any(f["provenance"] == "simulated" for f in d["findings"])
    assert len(client.get("/api/investigations").json()) == 1          # appears in history
    assert client.get("/api/stats").json()["total"] == 1


def test_data_survives_in_sqlite(client, fake_net):
    fake_net["rdap.org/domain"] = resp(404, {})
    fake_net["crt.sh"] = resp(200, [])
    fake_net["urlscan.io"] = resp(200, {"results": []})
    iid = client.post("/api/investigations", json={"target": "example.org"}).json()["id"]
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM findings WHERE investigation_id=?", (iid,)).fetchone()[0] > 0


def test_offline_does_not_crash(client):           # no fake_net: real calls fail in the sandbox, which is the offline case
    r = client.post("/api/investigations", json={"target": "example.com"})
    d = wait_done(client, r.json()["id"])
    assert d["status"] == "completed"
    assert any(f["provenance"] == "error" for f in d["findings"]) or d["finding_count"] > 0
    assert all(f["severity"] == "info" for f in d["findings"] if f["provenance"] == "error")


def test_ip_with_internetdb_flags_risk(client, fake_net):
    fake_net["rdap.org/ip"] = resp(200, {"name": "GOGL", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "country": "US", "entities": []})
    fake_net["ipwho.is"] = resp(200, {"success": True, "city": "X", "region": "Y", "country": "US", "connection": {"asn": 15169, "org": "Google", "isp": "Google"}})
    fake_net["internetdb"] = resp(200, {"ports": [53, 3389], "vulns": ["CVE-2020-0001"], "tags": ["scanner"], "hostnames": ["dns.google"]})
    fake_net["urlscan.io"] = resp(200, {"results": []})
    d = wait_done(client, client.post("/api/investigations", json={"target": "8.8.8.8"}).json()["id"])
    sev = {f["title"]: f["severity"] for f in d["findings"]}
    assert sev["1 candidate CVEs"] == "high" and sev["Sensitive services exposed"] == "medium"
    assert d["risk_score"] >= 35 and d["risk_label"] in ("High", "Moderate")


def test_hash_username_email_paths(client, fake_net):
    fake_net["hashlookup.circl.lu"] = resp(200, {"FileName": "empty", "source": "NSRL", "hashlookup:trust": 100})
    h = wait_done(client, client.post("/api/investigations", json={"target": "d41d8cd98f00b204e9800998ecf8427e"}).json()["id"])
    assert any("Known file" in f["title"] for f in h["findings"])

    fake_net["api.github.com/users"] = resp(200, {"html_url": "https://github.com/octocat", "name": "The Octocat", "public_repos": 8, "followers": 1, "created_at": "2011-01-25T00:00:00Z"})
    fake_net["gitlab.com"] = resp(200, [])
    fake_net["keybase.io"] = resp(200, {"them": [None]})
    fake_net["hub.docker.com"] = resp(404, {})
    fake_net["dev.to"] = resp(404, {})
    fake_net["hacker-news"] = resp(200, None)
    u = wait_done(client, client.post("/api/investigations", json={"target": "octocat"}).json()["id"])
    assert any(f["title"] == "Profile found on GitHub" for f in u["findings"])
    assert any("Found on 1 of 6" in f["title"] for f in u["findings"])

    fake_net["gravatar.com"] = resp(200, {})
    fake_net["api.github.com/search"] = resp(200, {"items": []})
    fake_net["rdap.org/domain"] = resp(200, RDAP)
    e = wait_done(client, client.post("/api/investigations", json={"target": "someone@mailinator.com"}).json()["id"])
    assert any(f["title"] == "Disposable e-mail provider" for f in e["findings"])
    assert any(f["title"] == "Gravatar profile exists" for f in e["findings"])


# ---------- keyed providers: success, bad key, rate limit, secrecy
def test_virustotal_with_key(client, fake_net, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "VTKEY-abcdef-123456")
    fake_net["virustotal.com"] = resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 50, "undetected": 5}, "reputation": -20}}})
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    fake_net["otx.alienvault.com"] = resp(200, {})
    d = wait_done(client, client.post("/api/investigations", json={"target": "evil-example.com"}).json()["id"])
    vt = next(f for f in d["findings"] if f["source"] == "VirusTotal")
    assert vt["severity"] == "critical" and vt["provenance"] == "live" and "12 of 67" in vt["title"]
    assert d["risk_score"] >= 40


@pytest.mark.parametrize("status,needle", [(401, "access denied"), (429, "rate limit")])
def test_bad_key_and_rate_limit_become_readable_errors(client, fake_net, monkeypatch, status, needle):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ABUSE-KEY-9999999")
    fake_net["abuseipdb.com"] = resp(status, {"errors": [{"detail": "x"}]})
    for k in ("rdap.org/ip", "ipwho.is", "internetdb", "urlscan.io"):
        fake_net[k] = httpx.ConnectError("down")
    d = wait_done(client, client.post("/api/investigations", json={"target": "1.1.1.1"}).json()["id"])
    err = next(f for f in d["findings"] if f["source"] == "AbuseIPDB")
    assert err["provenance"] == "error" and needle in err["detail"] and "ABUSE-KEY" not in err["detail"]


def test_timeout_is_reported(client, fake_net):
    fake_net["hashlookup"] = httpx.ReadTimeout("slow")
    d = wait_done(client, client.post("/api/investigations", json={"target": "d41d8cd98f00b204e9800998ecf8427e"}).json()["id"])
    assert any("timed out" in f["detail"] for f in d["findings"])


def test_keyed_lookups_can_be_switched_off(client, fake_net, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "VTKEY-abcdef-123456")
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    d = wait_done(client, client.post("/api/investigations", json={"target": "example.com", "use_keyed": False}).json()["id"])
    assert not any(f["source"] == "VirusTotal" for f in d["findings"])


def test_ai_summary_only_with_key_and_falls_back(client, fake_net, monkeypatch):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000000000")
    monkeypatch.setattr(providers, "http_post", lambda *a, **k: resp(200, {"choices": [{"message": {"content": "AI says: looks quiet."}}]}))
    d = wait_done(client, client.post("/api/investigations", json={"target": "example.com"}).json()["id"])
    assert d["summary"] == "AI says: looks quiet." and d["summary_source"].startswith("ai:")
    monkeypatch.setattr(providers, "http_post", lambda *a, **k: resp(500, {}))
    d = wait_done(client, client.post(f"/api/investigations/{d['id']}/rerun").json()["id"])
    assert d["summary_source"] == "rule-based" and "AI summary unavailable" in d["summary"]


# ---------- rerun, delete, alerts
def test_rerun_raises_alert_on_change(client, fake_net):
    fake_net["rdap.org/ip"] = resp(200, {"name": "N", "entities": []}); fake_net["ipwho.is"] = resp(200, {"success": False})
    fake_net["urlscan.io"] = resp(200, {"results": []})
    fake_net["internetdb"] = resp(200, {"ports": [80], "vulns": [], "tags": []})
    iid = client.post("/api/investigations", json={"target": "9.9.9.9"}).json()["id"]
    assert client.get("/api/alerts").json() == []                    # first run never alerts
    fake_net["internetdb"] = resp(200, {"ports": [80, 3389], "vulns": ["CVE-2021-1"], "tags": []})
    d = client.post(f"/api/investigations/{iid}/rerun").json()
    d = wait_done(client, iid)
    assert d["run_count"] == 2
    al = client.get("/api/alerts").json()
    assert len(al) == 1 and al[0]["severity"] == "high"
    assert "1 candidate CVEs" in al[0]["message"] and "Sensitive services exposed" in al[0]["message"]
    assert client.get("/api/stats").json()["unread_alerts"] == 1
    client.post("/api/alerts/read")
    assert client.get("/api/stats").json()["unread_alerts"] == 0


def test_same_target_is_reused_not_duplicated(client, fake_net):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    a = client.post("/api/investigations", json={"target": "example.com"}).json()["id"]
    b = client.post("/api/investigations", json={"target": "EXAMPLE.COM"}).json()["id"]
    assert a == b and len(client.get("/api/investigations").json()) == 1


def test_delete(client, fake_net):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    iid = client.post("/api/investigations", json={"target": "example.com", "monitoring": True}).json()["id"]
    assert client.delete(f"/api/investigations/{iid}").json() == {"ok": True}
    assert client.get(f"/api/investigations/{iid}").status_code == 404
    assert not scheduler.jobs()
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


# ---------- exports
def _seed(client, findings):
    with db.conn() as c:
        ts = engine.now()
        iid = c.execute("INSERT INTO investigations(target,target_type,created_at,updated_at,status,summary,summary_source) VALUES('example.com','domain',?,?,'completed','sum','rule-based')", (ts, ts)).lastrowid
        c.executemany("INSERT INTO findings(investigation_id,source,title,detail,severity,provenance,observed_at) VALUES(?,?,?,?,?,?,?)", [(iid, *f, ts) for f in findings])
    return iid


def test_csv_blocks_formula_injection(client):
    iid = _seed(client, [("DNS", "=HYPERLINK(\"http://evil\")", "+cmd|' /C calc'!A0", "info", "live"), ("DNS", "@SUM(A1)", "-2+3", "info", "live"), ("DNS", "normal", "fine, with comma", "low", "live")])
    r = client.get(f"/api/investigations/{iid}/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    import csv, io
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "investigation_id" and len(rows) == 4
    for row in rows[1:]:
        for cell in row[4:9]:
            assert cell[:1] not in ("=", "+", "-", "@")
    assert rows[1][5] == "'=HYPERLINK(\"http://evil\")"
    assert rows[3][8] == "fine, with comma"


def test_exports_handle_empty_cases(client):
    iid = _seed(client, [])
    assert client.get(f"/api/investigations/{iid}/export.csv").text.strip().count("\n") == 0
    p = client.get(f"/api/investigations/{iid}/export.pdf")
    assert p.headers["content-type"] == "application/pdf" and p.content.startswith(b"%PDF")


def test_pdf_with_findings_and_hostile_text(client):
    iid = _seed(client, [("DNS", "<b>bold</b> & <script>", "line1\nline2 <i>x</i>", "high", "live")] * 30)
    p = client.get(f"/api/investigations/{iid}/export.pdf")
    assert p.status_code == 200 and p.content.startswith(b"%PDF") and len(p.content) > 2000


# ---------- app API key guard
def test_api_key_guard(client, monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "a-long-random-server-key")
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/providers").status_code == 401
    assert isinstance(client.get("/api/providers").json()["detail"], str)
    assert client.get("/api/providers", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/providers", headers={"X-API-Key": "a-long-random-server-key"}).status_code == 200
    assert client.get("/").status_code == 200       # the page itself loads so the key dialog can appear


def test_security_headers_and_static(client):
    r = client.get("/")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200 and client.get("/static/style.css").status_code == 200
    assert "onclick=" not in r.text and "<script>" not in r.text      # CSP-safe: no inline scripts/handlers


# ---------- monitoring / scheduler
def test_scheduler_registers_jobs_without_duplicates(client, fake_net):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    iid = client.post("/api/investigations", json={"target": "example.com", "monitoring": True}).json()["id"]
    assert [j["id"] for j in scheduler.jobs()] == [f"mon-{iid}"]
    client.post("/api/investigations", json={"target": "example.com", "monitoring": True})
    client.patch(f"/api/investigations/{iid}/monitoring", json={"enabled": True})
    assert len(scheduler.jobs()) == 1
    assert client.get("/api/monitoring").json()["interval_seconds"] == 900
    client.patch(f"/api/investigations/{iid}/monitoring", json={"enabled": False})
    assert scheduler.jobs() == []


def test_scheduled_job_really_executes(client, fake_net, monkeypatch):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    monkeypatch.setattr(scheduler, "interval_seconds", lambda: 1)
    iid = client.post("/api/investigations", json={"target": "example.com", "monitoring": True}).json()["id"]
    deadline = time.time() + 10
    while time.time() < deadline and client.get(f"/api/investigations/{iid}").json()["run_count"] < 3:
        time.sleep(0.3)
    assert client.get(f"/api/investigations/{iid}").json()["run_count"] >= 3     # 1 manual + >=2 by the scheduler


def test_monitoring_jobs_restored_after_restart(client, fake_net):
    fake_net["rdap.org/domain"] = resp(404, {}); fake_net["crt.sh"] = resp(200, []); fake_net["urlscan.io"] = resp(200, {"results": []})
    iid = client.post("/api/investigations", json={"target": "example.com", "monitoring": True}).json()["id"]
    scheduler.shutdown(); assert scheduler.jobs() == []
    scheduler.start()
    assert [j["id"] for j in scheduler.jobs()] == [f"mon-{iid}"]


def test_concurrent_run_of_same_case_is_blocked():
    engine._running.add(4242)
    try:
        assert engine.execute(4242) is False
    finally:
        engine._running.discard(4242)


def test_scoring_and_labels():
    f = lambda s, p="live": {"severity": s, "provenance": p}
    assert engine.score_of([f("critical"), f("high")]) == 65 and engine.score_of([f("critical")] * 5) == 100
    assert engine.score_of([f("high", "error"), f("high", "system")]) == 0
    assert [engine.label_of(x) for x in (0, 10, 30, 60)] == ["Low", "Moderate", "High", "Critical"]
