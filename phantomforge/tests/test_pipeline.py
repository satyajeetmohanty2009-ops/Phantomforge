import asyncio
from pathlib import Path

import pytest

from backend.config import AppConfig
from backend.db import CrackedHash, Finding, Run, get_session, init_db
from backend.pipeline import EventBus, PipelineEngine, in_authorized_scope


def test_scope_matching():
    assert in_authorized_scope("192.0.2.10", "192.0.2.0/24")
    assert in_authorized_scope("https://app.example.test/login", "example.test")
    assert not in_authorized_scope("198.51.100.2", "192.0.2.0/24")


@pytest.mark.asyncio
async def test_mock_pipeline_end_to_end(tmp_path: Path):
    db_path = tmp_path / "pf.db"
    init_db(f"sqlite:///{db_path}")
    cfg = AppConfig(mock=True, database_url=f"sqlite:///{db_path}", runs_dir=str(tmp_path / "runs"), reports_dir=str(tmp_path / "reports"))
    bus = EventBus()
    engine = PipelineEngine(cfg, bus)
    run = engine.create_run("192.0.2.10", "192.0.2.0/24", {"auto_approve_gates": True})
    await engine.start(run.id)
    await asyncio.wait_for(engine.tasks[run.id], timeout=10)
    db = get_session()
    stored = db.get(Run, run.id)
    assert stored is not None
    assert stored.status == "DONE"
    assert stored.html_report and Path(stored.html_report).exists()
    assert db.query(Finding).filter_by(run_id=run.id).count() >= 5
    assert db.query(CrackedHash).filter_by(run_id=run.id).count() >= 1
    db.close()
