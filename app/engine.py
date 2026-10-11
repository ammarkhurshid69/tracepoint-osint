"""Runs an investigation: calls providers in parallel, scores, summarises, diffs against last run, raises alerts."""
import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx

from . import db, providers
from .providers import F, ProviderError

log = logging.getLogger("tracepoint")
WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_running: set[int] = set()
_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_running(inv_id):
    with _lock:
        return inv_id in _running


def score_of(findings):
    return min(100, sum(WEIGHT[f["severity"]] for f in findings if f["provenance"] == "live"))


def label_of(score):
    return "Low" if score < 10 else "Moderate" if score < 30 else "High" if score < 60 else "Critical"


def scrub(msg: str) -> str:
    for k, v in os.environ.items():
        if v and len(v) >= 8 and any(t in k for t in ("KEY", "TOKEN", "SECRET")):
            msg = msg.replace(v, "***")
    return msg


def run_one(p, ttype, target):
    try:
        return p.run(ttype, target)
    except ProviderError as e:
        return [F(p.name, "Lookup failed", scrub(str(e)), "info", "error")]
    except httpx.TimeoutException:
        return [F(p.name, "Lookup failed", f"{p.name}: request timed out.", "info", "error")]
    except httpx.HTTPError as e:
        return [F(p.name, "Lookup failed", f"{p.name}: could not reach the service ({type(e).__name__}). Check your internet connection.", "info", "error")]
    except Exception as e:  # never let one provider kill the whole run
        log.exception("provider %s crashed", p.id)
        return [F(p.name, "Lookup failed", f"{p.name}: internal error ({type(e).__name__}).", "info", "error")]


def rule_summary(ttype, target, findings, score, label):
    live = [f for f in findings if f["provenance"] == "live"]
    errs = sorted({f["source"] for f in findings if f["provenance"] == "error"})
    notable = sorted([f for f in live if f["severity"] != "info"], key=lambda f: RANK[f["severity"]])[:4]
    s = f"{len(live)} observations from {len({f['source'] for f in live})} sources for {ttype} {target}. "
    s += ("Notable: " + "; ".join(f"{f['title']} [{f['source']}, {f['severity']}]" for f in notable) + ". ") if notable \
        else "None of the sources that responded reported a risk signal. "
    if errs:
        s += "Unavailable or failed: " + ", ".join(errs) + ". "
    return s + f"Heuristic score {score}/100 ({label}); this is not a validated rating and missing findings do not prove safety."


def make_summary(ttype, target, findings, score, label, use_ai):
    base = rule_summary(ttype, target, findings, score, label)
    k, live = providers.key("OPENAI_API_KEY"), [f for f in findings if f["provenance"] == "live"]
    if not (use_ai and k and live):
        return base, "rule-based"
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    evidence = [{"source": f["source"], "title": f["title"], "detail": f["detail"][:300], "severity": f["severity"]} for f in live][:40]
    try:
        r = providers.http_post("https://api.openai.com/v1/chat/completions", headers={"Authorization": f"Bearer {k}"}, json={
            "model": model, "temperature": 0.2, "messages": [
                {"role": "system", "content": "You summarise OSINT evidence for a student security tool. Use ONLY the findings provided. "
                 "Do not invent facts, do not claim certainty, mention what could not be checked. Max 120 words, plain text."},
                {"role": "user", "content": json.dumps({"target": target, "type": ttype, "heuristic_score": score, "findings": evidence})}]})
        providers.check(r, "OpenAI")
        text = r.json()["choices"][0]["message"]["content"].strip()
        return text, f"ai:{model}"
    except Exception as e:
        return base + f" (AI summary unavailable: {scrub(str(e))[:80]})", "rule-based"


def keyset(rows):
    return {(f["source"], f["title"], f["severity"]) for f in rows if f["provenance"] == "live"}


def execute(inv_id: int) -> bool:
    with _lock:
        if inv_id in _running:
            return False
        _running.add(inv_id)
    try:
        _execute(inv_id)
        return True
    except Exception as e:
        log.exception("investigation %s failed", inv_id)
        with db.conn() as c:
            c.execute("UPDATE investigations SET status='failed', error=?, updated_at=? WHERE id=?", (scrub(str(e))[:300], now(), inv_id))
        return True
    finally:
        with _lock:
            _running.discard(inv_id)


def _execute(inv_id):
    with db.conn() as c:
        inv = c.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if not inv:
            return
        prev = [dict(r) for r in c.execute("SELECT * FROM findings WHERE investigation_id=?", (inv_id,))]
        c.execute("UPDATE investigations SET status='running', progress=5, error=NULL, updated_at=? WHERE id=?", (now(), inv_id))
    ttype, target, use_keyed = inv["target_type"], inv["target"], bool(inv["use_keyed"])
    plan = [p for p in providers.REGISTRY if ttype in p.types]
    active = [p for p in plan if p.kind != "key" or (use_keyed and p.configured())]
    skipped = [p.name for p in plan if p not in active]
    findings, done = [], 0
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(run_one, p, ttype, target) for p in active]
        for f in as_completed(futs):
            findings += f.result()
            done += 1
            with db.conn() as c:
                c.execute("UPDATE investigations SET progress=? WHERE id=?", (5 + int(85 * done / len(futs)), inv_id))
    if skipped:
        findings.append(F("System", "API sources not queried", "No key configured (or keyed lookups switched off) for: " + ", ".join(skipped) +
                          ". Add keys to the .env file to include them.", "info", "system"))
    ts = now()
    score = score_of(findings)
    label = label_of(score)
    summary, src = make_summary(ttype, target, findings, score, label, use_keyed)
    findings.sort(key=lambda f: (f["source"], RANK[f["severity"]]))
    with db.conn() as c:
        if inv["run_count"] > 0:
            _raise_alerts(c, inv, prev, findings, label)
        c.execute("DELETE FROM findings WHERE investigation_id=?", (inv_id,))
        c.executemany("INSERT INTO findings(investigation_id,source,title,detail,severity,provenance,observed_at) VALUES(?,?,?,?,?,?,?)",
                      [(inv_id, f["source"], f["title"], f["detail"], f["severity"], f["provenance"], ts) for f in findings])
        c.execute("UPDATE investigations SET status='completed', progress=100, risk_score=?, risk_label=?, summary=?, summary_source=?, "
                  "run_count=run_count+1, last_run_at=?, updated_at=? WHERE id=?", (score, label, summary, src, ts, ts, inv_id))


def _raise_alerts(c, inv, prev, new, new_label):
    old, cur = keyset(prev), keyset(new)
    added = [k for k in cur - old if k[2] != "info"]
    gone = [k for k in old - cur if k[2] != "info"]
    parts, sev = [], "info"
    if added:
        parts.append("New: " + "; ".join(f"{t} ({s})" for _, t, s in sorted(added, key=lambda k: RANK[k[2]])[:5]))
        sev = min((k[2] for k in added), key=lambda s: RANK[s])
    if gone:
        parts.append("No longer seen: " + "; ".join(t for _, t, _ in gone[:5]))
    if inv["risk_label"] != new_label and inv["run_count"] > 0:
        parts.append(f"Risk level {inv['risk_label']} -> {new_label}")
    if parts:
        c.execute("INSERT INTO alerts(investigation_id,target,message,severity,created_at) VALUES(?,?,?,?,?)",
                  (inv["id"], inv["target"], " | ".join(parts), sev, now()))
