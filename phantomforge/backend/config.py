from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ToolPaths(BaseModel):
    nmap: str = "/usr/bin/nmap"
    tshark: str = "/usr/bin/tshark"
    sqlmap: str = "/usr/bin/sqlmap"
    john: str = "/usr/bin/john"
    beef: str = "/usr/share/beef-xss/beef"


class Defaults(BaseModel):
    nmap_flags: str = "-sV -sC -O --top-ports 1000"
    nmap_timing: str = "-T3"
    nmap_vuln_scripts: bool = False
    sqlmap_flags: str = "--batch --random-agent --threads=2 --crawl=1 --level=1 --risk=1"
    tshark_interface: str = "eth0"
    capture_duration: int = 30
    john_wordlist: str = "/usr/share/wordlists/rockyou.txt.gz"


class BeefConfig(BaseModel):
    base_url: str = "http://127.0.0.1:3000"
    username: str = "beef"
    password: str = "beef"
    hook_url: str = "http://127.0.0.1:3000/hook.js"
    beef_start_on_run: bool = False


class AppConfig(BaseModel):
    mock: bool = False
    database_url: str = "sqlite:///./phantomforge.db"
    reports_dir: str = "reports"
    runs_dir: str = "runs"
    concurrency_limit: int = Field(default=2, ge=1)
    allow_destructive: bool = False
    gate_before_sqlmap: bool = True
    gate_before_beef: bool = True
    gate_before_crack: bool = True
    tools: ToolPaths = Field(default_factory=ToolPaths)
    defaults: Defaults = Field(default_factory=Defaults)
    beef: BeefConfig = Field(default_factory=BeefConfig)
    config_path: str = "config.yaml"


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.environ.get("PHANTOMFORGE_CONFIG", "config.yaml"))
    data: dict[str, Any] = {}
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    cfg = AppConfig(**data)
    cfg.config_path = str(config_path)
    if os.environ.get("MOCK_TOOLS") == "1":
        cfg.mock = True
    return cfg
