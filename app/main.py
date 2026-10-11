"""Tracepoint: OSINT investigation desk. FastAPI app: routes only; logic lives in engine/providers/reports."""
import hmac
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent.parent / ".env")   # project-root .env, whatever the current folder is
from . import db, detect, engine, providers, reports, scheduler  # noqa: E402

logging.getLogger("httpx").setLevel(logging.WARNING)   # httpx logs full URLs, which can contain keys
logging.getLogger("httpcore").setLevel(logging.WARNING)
STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app):
    db.init()
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title="Tracepoint OSINT Desk", version="2.0.0", lifespan=lifespan)


@app.middleware("http")
async def guard(request: Request, call_next):
    path, secret = request.url.path, os.getenv("APP_API_KEY", "")
    if secret and path.startswith("/api/") and path != "/api/health":
        if not hmac.compare_digest(request.headers.get("x-api-key", ""), secret):
            return JSONResponse({"detail": "Unauthorized: missing or wrong API key."}, status_code=401)
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})
    if not path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
    return resp


@app.exception_handler(RequestValidationError)
async def validation_handler(request, exc):
    msgs = [f"{'.'.join(str(x) for x in e['loc'][1:]) or 'input'}: {e['msg']}" for e in exc.errors()]
    return JSONResponse({"detail": "; ".join(msgs)}, status_code=422)   # always a plain string


@app.exception_handler(Exception)
async def crash_handler(request, exc):
    logging.getLogger("tracepoint").exception("unhandled error")
    return JSONResponse({"detail": "Internal server error. See the server console for details."}, status_code=500)


class NewCase(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    target_type: Literal["auto", "domain", "ip", "url", "email", "hash", "username"] = "auto"
    monitoring: bool = False
    use_keyed: bool = True


class MonitorToggle(BaseModel):
    enabled: bool


def _inv(c, iid, with_findings=False):
    r = c.execute("SELECT * FROM investigations WHERE id=?", (iid,)).fetchone()
    if not r:
        raise HTTPException(404, "Investigation not found.")
    d = dict(r)
    d["monitoring"], d["use_keyed"] = bool(d["monitoring"]), bool(d["use_keyed"])
    d["finding_count"] = c.execute("SELECT COUNT(*) FROM findings WHERE investigation_id=?", (iid,)).fetchone()[0]
    if with_findings:
        rows = c.execute("SELECT source,title,detail,severity,provenance,observed_at FROM findings WHERE investigation_id=? ORDER BY source,id", (iid,))
        d["findings"] = [dict(x) for x in rows]
    return d


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version, "scheduler_jobs": len(scheduler.jobs())}


@app.get("/api/detect")
def detect_type(q: str = ""):
    try:
        t, v = detect.normalize(q)
        return {"ok": True, "type": t, "label": detect.LABELS[t], "value": v}
    except ValueError as e:
        return {"ok": False, "message": str(e)}


@app.get("/api/providers")
def provider_status():
    items = [{"id": p.id, "name": p.name, "kind": p.kind, "configured": p.configured(), "types": list(p.types),
              "description": p.desc, "env_var": p.env} for p in providers.REGISTRY]
    return {"providers": items, "ai": {"configured": bool(providers.key("OPENAI_API_KEY")), "env_var": "OPENAI_API_KEY"},
            "note": "'configured' means a key is present. It does not prove the key is valid."}


@app.get("/api/stats")
def stats():
    with db.conn() as c:
        one = lambda q: c.execute(q).fetchone()[0]
        by = {r[0]: r[1] for r in c.execute("SELECT risk_label, COUNT(*) FROM investigations WHERE status='completed' GROUP BY risk_label")}
        return {"total": one("SELECT COUNT(*) FROM investigations"), "running": one("SELECT COUNT(*) FROM investigations WHERE status IN ('queued','running')"),
                "findings": one("SELECT COUNT(*) FROM findings WHERE provenance='live'"), "monitored": one("SELECT COUNT(*) FROM investigations WHERE monitoring=1"),
                "unread_alerts": one("SELECT COUNT(*) FROM alerts WHERE is_read=0"), "by_risk": by}


@app.post("/api/investigations", status_code=201)
def create(body: NewCase, bg: BackgroundTasks):
    try:
        ttype, target = detect.normalize(body.target, body.target_type)
    except ValueError as e:
        raise HTTPException(422, str(e))
    with db.conn() as c:
        row = c.execute("SELECT id FROM investigations WHERE target=? AND target_type=?", (target, ttype)).fetchone()
        ts = engine.now()
        if row:
            iid = row["id"]
            c.execute("UPDATE investigations SET monitoring=?, use_keyed=?, status='queued', progress=0, updated_at=? WHERE id=?",
                      (int(body.monitoring), int(body.use_keyed), ts, iid))
        else:
            iid = c.execute("INSERT INTO investigations(target,target_type,monitoring,use_keyed,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                            (target, ttype, int(body.monitoring), int(body.use_keyed), ts, ts)).lastrowid
        out = _inv(c, iid)
    (scheduler.add_job if body.monitoring else scheduler.remove_job)(iid)
    bg.add_task(engine.execute, iid)
    return out


@app.get("/api/investigations")
def list_all(q: str = ""):
    with db.conn() as c:
        rows = c.execute("SELECT id FROM investigations WHERE target LIKE ? ORDER BY updated_at DESC, id DESC", (f"%{q}%",)).fetchall()
        return [_inv(c, r["id"]) for r in rows]


@app.get("/api/investigations/{iid}")
def get_one(iid: int):
    with db.conn() as c:
        return _inv(c, iid, True)


@app.post("/api/investigations/{iid}/rerun")
def rerun(iid: int, bg: BackgroundTasks):
    with db.conn() as c:
        _inv(c, iid)
        if not engine.is_running(iid):
            c.execute("UPDATE investigations SET status='queued', progress=0 WHERE id=?", (iid,))
        out = _inv(c, iid)
    bg.add_task(engine.execute, iid)
    return out


@app.patch("/api/investigations/{iid}/monitoring")
def toggle(iid: int, body: MonitorToggle):
    with db.conn() as c:
        _inv(c, iid)
        c.execute("UPDATE investigations SET monitoring=? WHERE id=?", (int(body.enabled), iid))
        out = _inv(c, iid)
    (scheduler.add_job if body.enabled else scheduler.remove_job)(iid)
    return out


@app.delete("/api/investigations/{iid}")
def delete(iid: int):
    with db.conn() as c:
        _inv(c, iid)
        c.execute("DELETE FROM investigations WHERE id=?", (iid,))
    scheduler.remove_job(iid)
    return {"ok": True}


@app.get("/api/investigations/{iid}/export.csv")
def export_csv(iid: int):
    with db.conn() as c:
        d = _inv(c, iid, True)
    return Response(reports.to_csv(d, d["findings"]), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="investigation_{iid}.csv"'})


@app.get("/api/investigations/{iid}/export.pdf")
def export_pdf(iid: int):
    with db.conn() as c:
        d = _inv(c, iid, True)
    return Response(reports.to_pdf(d, d["findings"]), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="investigation_{iid}.pdf"'})


@app.get("/api/alerts")
def alerts():
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200")]


@app.post("/api/alerts/read")
def alerts_read():
    with db.conn() as c:
        c.execute("UPDATE alerts SET is_read=1")
    return {"ok": True}


@app.get("/api/monitoring")
def monitoring():
    return {"interval_seconds": scheduler.interval_seconds(), "jobs": scheduler.jobs()}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
db.init()
