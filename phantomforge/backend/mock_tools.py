from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, AsyncIterator

from .tools.base import ToolRunner


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/><script id="http-title" output="Phantom demo"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Samba" version="4.17"/></port></ports></host>
<host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Apache httpd" version="2.4.58"/></port></ports></host></nmaprun>"""


class MockNmapTool(ToolRunner):
    name = "mock-nmap"
    async def run(self, target: str, options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        yield f"$ nmap mock scan {target}"
        for line in ["Host discovery complete", "192.0.2.10:80 open http nginx", "192.0.2.10:445 open smb", "192.0.2.20:443 open https"]:
            await asyncio.sleep(0.05)
            yield line
        (self.run_dir / "nmap.xml").write_text(NMAP_XML, encoding="utf-8")
        yield "[exit 0]"


class MockTsharkTool(ToolRunner):
    name = "mock-tshark"
    async def run(self, mode: str = "capture", options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        yield "$ tshark mock capture/analyze"
        await asyncio.sleep(0.05)
        text = "HTTP Authorization: Basic demo:drowssap\nalice::DOMAIN:1122334455667788:abcdef0123456789:0101000000000000\nhttps://demo.local/login token=abc123 admin@example.test"
        (self.run_dir / "tshark_analysis.txt").write_text(text, encoding="utf-8")
        (self.run_dir / "hashes_netntlmv2.txt").write_text("alice::DOMAIN:1122334455667788:abcdef0123456789:0101000000000000\n", encoding="utf-8")
        yield "Captured HTTP credentials and one NetNTLMv2 challenge-response"
        yield "[exit 0]"


class MockSqlmapTool(ToolRunner):
    name = "mock-sqlmap"
    async def run(self, urls: list[str], options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        out = self.run_dir / "sqlmap"
        out.mkdir(exist_ok=True)
        yield f"$ sqlmap mock against {len(urls)} URL(s)"
        await asyncio.sleep(0.05)
        data = [{"url": urls[0] if urls else "http://example.test/", "parameter": "id", "injection_type": "boolean-based blind", "payload": "id=1 AND 1=1", "dbms": "MySQL", "hashes": [{"format": "md5crypt", "hash": "$1$demo$C6UzMDM.H6dfI/f/IKc3L."}]}]
        import json
        (out / "results.json").write_text(json.dumps(data), encoding="utf-8")
        (self.run_dir / "hashes_md5crypt.txt").write_text("$1$demo$C6UzMDM.H6dfI/f/IKc3L.\n", encoding="utf-8")
        yield "sqlmap identified injectable parameter id"
        yield "[exit 0]"


class MockBeefTool(ToolRunner):
    name = "mock-beef"
    async def run(self, hook_url: str | None = None, poll_seconds: int = 2) -> AsyncIterator[str]:
        yield f"Hook URL: {hook_url or self.config.beef.hook_url}"
        await asyncio.sleep(0.05)
        yield "Hooked browsers online: 1"
        (self.run_dir / "beef_sessions.json").write_text('[{"id":"sess-1","ip":"192.0.2.55","browser":"Firefox","os":"Linux","hooked_at":"now"}]', encoding="utf-8")


class MockJohnTool(ToolRunner):
    name = "mock-john"
    async def run(self, hash_files: list[str], fmt: str = "nt") -> AsyncIterator[str]:
        yield f"$ john mock --format={fmt} {' '.join(hash_files)}"
        await asyncio.sleep(0.05)
        (self.run_dir / "john_show.txt").write_text("alice:Password123\n$1$demo$C6UzMDM.H6dfI/f/IKc3L.:secret\n2 password hashes cracked\n", encoding="utf-8")
        yield "alice:Password123"
        yield "$1$demo$C6UzMDM.H6dfI/f/IKc3L.:secret"
