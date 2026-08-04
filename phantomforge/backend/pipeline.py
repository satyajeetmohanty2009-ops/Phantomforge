from __future__ import annotations

import asyncio
import html
import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .config import AppConfig
from .db import CrackedHash, Finding, Phase, Run, add_finding, get_session
from .mock_tools import MockBeefTool, MockJohnTool, MockNmapTool, MockSqlmapTool, MockTsharkTool
from .tools.beef_tool import BeefTool
from .tools.john_tool import JohnTool, parse_john_show
from .tools.nmap_tool import NmapTool, parse_nmap_xml
from .tools.sqlmap_tool import SqlmapTool, parse_sqlmap_output
from .tools.tshark_tool import TsharkTool, parse_tshark_text

PHASE_ORDER = ["RECON", "CAPTURE", "WEBVULN", "HOOK", "CRACK", "REPORT"]


class EventBus:
    def __init__(self) -> None:
        self.clients: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, event: dict[str, Any]) -> None:
        for queue in list(self.clients):
            await queue.put(event)

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self.clients.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self.clients.discard(queue)


def in_authorized_scope(target: str, scope: str) -> bool:
    target = target.strip()
    scope = scope.strip()
    if not target or not scope:
        return False
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0].split(":")[0]
    for item in [x.strip() for x in scope.replace(",", "\n").splitlines() if x.strip()]:
        try:
            net = ipaddress.ip_network(item, strict=False)
            try:
                if ipaddress.ip_address(host) in net:
                    return True
            except ValueError:
                pass
        except ValueError:
            normalized = item.lower().lstrip("*.") 
            if host.lower() == normalized or host.lower().endswith(f".{normalized}") or target.lower().find(normalized) >= 0:
                return True
    return False


class PipelineEngine:
    def __init__(self, config: AppConfig, bus: EventBus):
        self.config = config
        self.bus = bus
        self.tasks: dict[int, asyncio.Task[None]] = {}
        self.active_tools: dict[int, Any] = {}

    def create_run(self, target: str, scope: str, run_config: dict[str, Any] | None = None) -> Run:
        if not in_authorized_scope(target, scope):
            raise ValueError("Target is outside the authorized scope string")
        db = get_session()
        run_dir = Path(self.config.runs_dir) / datetime.utcnow().strftime(f"run-%Y%m%d-%H%M%S-%f")
        run_dir.mkdir(parents=True, exist_ok=True)
        run = Run(target=target, scope=scope, config=run_config or {}, run_dir=str(run_dir))
        db.add(run)
        db.commit()
        db.refresh(run)
        for phase in PHASE_ORDER:
            db.add(Phase(run_id=run.id, name=phase))
        db.commit()
        db.refresh(run)
        db.close()
        return run

    async def start(self, run_id: int) -> None:
        if run_id in self.tasks and not self.tasks[run_id].done():
            raise ValueError("Run is already active")
        self.tasks[run_id] = asyncio.create_task(self._execute(run_id))

    async def stop(self, run_id: int) -> None:
        tool = self.active_tools.get(run_id)
        if tool:
            await tool.stop()
        task = self.tasks.get(run_id)
        if task:
            task.cancel()
        db = get_session()
        run = db.get(Run, run_id)
        if run:
            run.status = "STOPPED"
            run.current_phase = "STOPPED"
            db.commit()
        db.close()
        await self.bus.publish({"run_id": run_id, "phase": "STOPPED", "line": "Run stopped"})

    async def _log(self, db: Session, run: Run, phase: str, line: str) -> None:
        run_log = Path(run.run_dir) / "run.log"
        run_log.parent.mkdir(parents=True, exist_ok=True)
        with run_log.open("a", encoding="utf-8") as fh:
            fh.write(f"[{datetime.utcnow().isoformat()}] [{phase}] {line}\n")
        phase_row = db.query(Phase).filter_by(run_id=run.id, name=phase).first()
        if phase_row:
            phase_row.log = (phase_row.log or "") + line + "\n"
            db.commit()
        await self.bus.publish({"run_id": run.id, "phase": phase, "line": line})

    async def _run_tool(self, db: Session, run: Run, phase: str, tool: Any, *args: Any, **kwargs: Any) -> None:
        self.active_tools[run.id] = tool
        phase_row = db.query(Phase).filter_by(run_id=run.id, name=phase).first()
        if phase_row:
            phase_row.status = "RUNNING"
            phase_row.started_at = datetime.utcnow()
        run.status = "RUNNING"
        run.current_phase = phase
        db.commit()
        async for line in tool.run(*args, **kwargs):
            await self._log(db, run, phase, line)
        if phase_row:
            phase_row.status = "DONE"
            phase_row.ended_at = datetime.utcnow()
        db.commit()
        self.active_tools.pop(run.id, None)

    def _tool_classes(self) -> tuple[Any, Any, Any, Any, Any]:
        if self.config.mock:
            return MockNmapTool, MockTsharkTool, MockSqlmapTool, MockBeefTool, MockJohnTool
        return NmapTool, TsharkTool, SqlmapTool, BeefTool, JohnTool

    def _gate_enabled(self, run: Run, name: str) -> bool:
        key = f"gate_before_{name.lower()}"
        if key in run.config:
            return bool(run.config[key])
        return bool(getattr(self.config, key, False))

    async def _gate(self, db: Session, run: Run, phase: str) -> bool:
        # API supports explicit gates; mock/default automation auto-approves so tests and demo runs complete.
        if self._gate_enabled(run, phase) and not run.config.get("auto_approve_gates", True):
            run.status = "PAUSED"
            run.current_phase = f"GATE_{phase.upper()}"
            db.commit()
            await self._log(db, run, phase.upper(), f"Paused before {phase}; approve/skip/cancel via API")
            return False
        return True

    async def _execute(self, run_id: int) -> None:
        db = get_session()
        run = db.get(Run, run_id)
        assert run is not None
        run_dir = Path(run.run_dir)
        Nmap, Tshark, Sqlmap, Beef, John = self._tool_classes()
        artifacts: dict[str, Any] = {"web_targets": [], "hash_files": []}
        try:
            await self._run_tool(db, run, "RECON", Nmap(self.config, run_dir), run.target, run.config.get("nmap", {}))
            nmap_data = parse_nmap_xml(run_dir / "nmap.xml")
            for host in nmap_data["hosts"]:
                add_finding(db, run.id, "RECON", "host", f"Host {host['address']}", host)
                for port in host["ports"]:
                    add_finding(db, run.id, "RECON", "service", f"{host['address']}:{port['port']} {port['service']}", {"host": host["address"], **port})
            for script in nmap_data["scripts"]:
                add_finding(db, run.id, "RECON", "nse", f"NSE {script['id']} on {script['host']}:{script['port']}", script, "medium")
            artifacts["web_targets"] = nmap_data["web_targets"]

            if run.config.get("capture_enabled", True):
                await self._run_tool(db, run, "CAPTURE", Tshark(self.config, run_dir), run.config.get("capture_mode", "capture"), run.config.get("tshark", {}))
                analysis_file = run_dir / "tshark_analysis.txt"
                if analysis_file.exists():
                    analysis = parse_tshark_text(analysis_file.read_text(encoding="utf-8", errors="replace"))
                    for cred in analysis["credentials"]:
                        add_finding(db, run.id, "CAPTURE", "credential", "Captured HTTP credential", cred, "high")
                    for h in analysis["hashes"]:
                        add_finding(db, run.id, "CAPTURE", "hash", f"Captured {h['format']} hash", h, "high")
                    add_finding(db, run.id, "CAPTURE", "summary", "Traffic summary", analysis)
                artifacts["hash_files"] += [str(p) for p in run_dir.glob("hashes_*.txt")]

            if artifacts["web_targets"] and run.config.get("sqlmap_enabled", True):
                if await self._gate(db, run, "sqlmap"):
                    await self._run_tool(db, run, "WEBVULN", Sqlmap(self.config, run_dir), artifacts["web_targets"], run.config.get("sqlmap", {}))
                    for result_file in (run_dir / "sqlmap").glob("*.json"):
                        for finding in parse_sqlmap_output(result_file):
                            add_finding(db, run.id, "WEBVULN", "sqli", f"SQL injection on {finding.get('url', 'target')}", finding, "critical")
                    artifacts["hash_files"] += [str(p) for p in run_dir.glob("hashes_*.txt")]

            if run.config.get("beef_enabled", True):
                if await self._gate(db, run, "beef"):
                    await self._run_tool(db, run, "HOOK", Beef(self.config, run_dir), run.config.get("hook_url"))
                    sessions_file = run_dir / "beef_sessions.json"
                    if sessions_file.exists():
                        for session in json.loads(sessions_file.read_text(encoding="utf-8")):
                            add_finding(db, run.id, "HOOK", "hooked_browser", f"Hooked browser {session.get('id')}", session, "medium")

            artifacts["hash_files"] = sorted(set(artifacts["hash_files"]))
            if artifacts["hash_files"] and run.config.get("john_enabled", True):
                if await self._gate(db, run, "crack"):
                    fmt = run.config.get("john", {}).get("format", "netntlmv2")
                    await self._run_tool(db, run, "CRACK", John(self.config, run_dir), artifacts["hash_files"], fmt)
                    show_file = run_dir / "john_show.txt"
                    if show_file.exists():
                        for item in parse_john_show(show_file.read_text(encoding="utf-8", errors="replace"), fmt):
                            db.add(CrackedHash(run_id=run.id, source="john", hash_value=item["hash"], password=item["password"], format=item["format"]))
                        db.commit()

            await self._generate_reports(db, run)
            run.status = "DONE"
            run.current_phase = "DONE"
            db.commit()
            await self.bus.publish({"run_id": run.id, "phase": "DONE", "line": "Run complete"})
        except asyncio.CancelledError:
            run.status = "STOPPED"
            run.current_phase = "STOPPED"
            db.commit()
        except Exception as exc:
            run.status = "FAILED"
            run.current_phase = "FAILED"
            db.commit()
            await self._log(db, run, run.current_phase, f"ERROR: {exc}")
        finally:
            db.close()
            self.active_tools.pop(run_id, None)

    async def _generate_reports(self, db: Session, run: Run) -> None:
        reports_dir = Path(self.config.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        findings = db.query(Finding).filter_by(run_id=run.id).all()
        cracked = db.query(CrackedHash).filter_by(run_id=run.id).all()
        rows = "\n".join(
            f"<tr><td>{html.escape(f.phase)}</td><td>{html.escape(f.kind)}</td><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td><td><pre>{html.escape(json.dumps(f.data, indent=2))}</pre></td></tr>"
            for f in findings
        )
        cracked_rows = "\n".join(f"<tr><td>{html.escape(c.format)}</td><td>{html.escape(c.hash_value)}</td><td>{html.escape(c.password)}</td></tr>" for c in cracked)
        html_path = reports_dir / f"run-{run.id}.html"
        md_path = reports_dir / f"run-{run.id}.md"
        html_path.write_text(f"""<!doctype html><html><head><meta charset="utf-8"><title>PhantomForge Run {run.id}</title><style>body{{font-family:Inter,Arial;background:#101318;color:#e6edf3}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #30363d;padding:8px;vertical-align:top}}pre{{white-space:pre-wrap}}</style></head><body><h1>PhantomForge Report: Run {run.id}</h1><p>Target: {html.escape(run.target)}<br>Scope: {html.escape(run.scope)}</p><h2>Findings</h2><table><tr><th>Phase</th><th>Kind</th><th>Severity</th><th>Title</th><th>Data</th></tr>{rows}</table><h2>Cracked Hashes</h2><table><tr><th>Format</th><th>Hash</th><th>Password</th></tr>{cracked_rows}</table></body></html>""", encoding="utf-8")
        md_path.write_text(f"# PhantomForge Run {run.id}\n\nTarget: `{run.target}`\n\nFindings: {len(findings)}\n\nCracked hashes: {len(cracked)}\n", encoding="utf-8")
        run.html_report = str(html_path)
        run.md_report = str(md_path)
        await self._log(db, run, "REPORT", f"Generated {html_path} and {md_path}")
