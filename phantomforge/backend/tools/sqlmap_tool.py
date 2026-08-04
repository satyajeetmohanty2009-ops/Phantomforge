from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, AsyncIterator

from .base import ToolRunner


def parse_sqlmap_output(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    findings.append(item)
        elif isinstance(data, dict):
            entries = data.get("data") or data.get("results") or [data]
            for item in entries if isinstance(entries, list) else [entries]:
                if isinstance(item, dict):
                    findings.append(item)
        return findings
    except json.JSONDecodeError:
        pass
    current: dict[str, Any] = {}
    for line in text.splitlines():
        if "Parameter:" in line:
            current["parameter"] = line.split("Parameter:", 1)[1].strip()
        if "Type:" in line:
            current["injection_type"] = line.split("Type:", 1)[1].strip()
        if "Payload:" in line:
            current["payload"] = line.split("Payload:", 1)[1].strip()
        dbms = re.search(r"back-end DBMS:\s*(.+)", line, re.I)
        if dbms:
            current["dbms"] = dbms.group(1).strip()
        if current and ("sqlmap identified" in line or "Payload:" in line):
            findings.append(dict(current))
    return findings


class SqlmapTool(ToolRunner):
    name = "sqlmap"

    async def run(self, urls: list[str], options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        options = options or {}
        output_dir = self.run_dir / "sqlmap"
        output_dir.mkdir(exist_ok=True)
        flags = (options.get("flags") or self.config.defaults.sqlmap_flags).split()
        if not self.config.allow_destructive:
            flags = [f for f in flags if f not in {"--os-shell", "--sql-shell"}]
            flags += ["--no-cast", "--smart"]
        for url in urls:
            command = [self.config.tools.sqlmap, "-u", url, f"--output-dir={output_dir}", "--flush-session", *flags]
            async for line in self.stream_process(command):
                yield line
