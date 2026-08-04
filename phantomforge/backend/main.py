from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .config import load_config
from .db import CrackedHash, Finding, Run, Target, get_session, init_db
from .pipeline import EventBus, PipelineEngine

ROOT = Path(__file__).resolve().parents[1]
cfg = load_config(ROOT / "config.yaml")
init_db(cfg.database_url)
bus = EventBus()
engine = PipelineEngine(cfg, bus)
app = FastAPI(title="PhantomForge")


def db_dep():
    db = get_session()
    try:
        yield db
    finally:
        db.close()


class TargetIn(BaseModel):
    value: str


class RunIn(BaseModel):
    target: str
    scope: str
    config: dict[str, Any] = {}


@app.get("/api/config")
def get_config():
    data = cfg.model_dump()
    data["beef"]["password"] = "***"
    return data


@app.get("/api/targets")
def list_targets(db: Session = Depends(db_dep)):
    return [{"id": t.id, "value": t.value} for t in db.query(Target).order_by(Target.created_at.desc()).all()]


@app.post("/api/targets")
def add_target(payload: TargetIn, db: Session = Depends(db_dep)):
    target = Target(value=payload.value.strip())
    db.add(target)
    try:
        db.commit()
    except Exception:
        db.rollback()
    return {"ok": True}


@app.post("/api/runs")
async def create_run(payload: RunIn):
    try:
        run = engine.create_run(payload.target, payload.scope, payload.config)
        await engine.start(run.id)
        return {"id": run.id}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/runs")
def list_runs(db: Session = Depends(db_dep)):
    runs = db.query(Run).order_by(Run.created_at.desc()).all()
    return [{"id": r.id, "target": r.target, "status": r.status, "phase": r.current_phase, "created_at": r.created_at.isoformat(), "html_report": r.html_report} for r in runs]


@app.get("/api/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(db_dep)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404)
    return {"id": run.id, "target": run.target, "scope": run.scope, "status": run.status, "phase": run.current_phase, "config": run.config}


@app.post("/api/runs/{run_id}/stop")
async def stop_run(run_id: int):
    await engine.stop(run_id)
    return {"ok": True}


@app.get("/api/findings")
def findings(run_id: int | None = None, db: Session = Depends(db_dep)):
    q = db.query(Finding)
    if run_id:
        q = q.filter_by(run_id=run_id)
    return [{"id": f.id, "run_id": f.run_id, "phase": f.phase, "kind": f.kind, "title": f.title, "severity": f.severity, "data": f.data} for f in q.order_by(Finding.created_at.desc()).all()]


@app.get("/api/cracked")
def cracked(run_id: int | None = None, db: Session = Depends(db_dep)):
    q = db.query(CrackedHash)
    if run_id:
        q = q.filter_by(run_id=run_id)
    return [{"run_id": c.run_id, "source": c.source, "format": c.format, "hash": c.hash_value, "password": c.password} for c in q.order_by(CrackedHash.created_at.desc()).all()]


@app.post("/api/pcaps")
async def upload_pcap(file: UploadFile = File(...)):
    dest = ROOT / "runs" / "uploads"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / Path(file.filename or "upload.pcap").name
    path.write_bytes(await file.read())
    return {"path": str(path)}


@app.get("/api/reports/{run_id}/{kind}")
def report(run_id: int, kind: str, db: Session = Depends(db_dep)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404)
    path = run.html_report if kind == "html" else run.md_report
    if not path or not Path(path).exists():
        raise HTTPException(404)
    return FileResponse(path)


@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws.accept()
    queue = await bus.subscribe()
    try:
        while True:
            event = await queue.get()
            await ws.send_json(event)
    except WebSocketDisconnect:
        bus.unsubscribe(queue)
    except asyncio.CancelledError:
        bus.unsubscribe(queue)
        raise


static_dir = ROOT / "frontend" / "dist"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
