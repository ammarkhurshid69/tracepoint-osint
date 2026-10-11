"""Recurring monitoring using APScheduler. One job per monitored investigation (id 'mon-<id>')."""
import os

from apscheduler.schedulers.background import BackgroundScheduler

from . import db, engine

_sched: BackgroundScheduler | None = None


def interval_seconds() -> float:
    return float(os.getenv("MONITOR_INTERVAL_MINUTES", "15")) * 60


def start():
    global _sched
    if _sched and _sched.running:
        return
    _sched = BackgroundScheduler(timezone="UTC")
    _sched.start()
    with db.conn() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM investigations WHERE monitoring=1")]
    for i in ids:
        add_job(i)


def shutdown():
    global _sched
    if _sched and _sched.running:
        _sched.shutdown(wait=False)
    _sched = None


def add_job(inv_id: int):
    """replace_existing + max_instances=1 means toggling twice never creates duplicate jobs."""
    if _sched and _sched.running:
        _sched.add_job(engine.execute, "interval", seconds=interval_seconds(), args=[inv_id], id=f"mon-{inv_id}",
                       replace_existing=True, max_instances=1, coalesce=True)


def remove_job(inv_id: int):
    if _sched and _sched.running and _sched.get_job(f"mon-{inv_id}"):
        _sched.remove_job(f"mon-{inv_id}")


def jobs():
    if not (_sched and _sched.running):
        return []
    return [{"id": j.id, "next_run": j.next_run_time.isoformat() if j.next_run_time else None} for j in _sched.get_jobs()]
