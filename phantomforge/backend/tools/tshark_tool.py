from __future__ import annotations

import re
from pathlib import Path
from typing import Any, AsyncIterator

from .base import ToolRunner


NTLM_RE = re.compile(r"([A-Za-z0-9_.-]+::[^:\s]+:[0-9A-Fa-f]{16}:[0-9A-Fa-f]+:[0-9A-Fa-f]+)")


def parse_tshark_text(text: str) -> dict[str, Any]:
    creds = []
    hashes = []
    urls = sorted(set(re.findall(r"https?://[^\s\"']+", text)))
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)))
    for line in text.splitlines():
        if "Authorization: Basic" in line:
            creds.append({"type": "http_basic", "raw": line.strip()})
        for match in NTLM_RE.findall(line):
            hashes.append({"format": "netntlmv2", "hash": match})
    return {"credentials": creds, "hashes": hashes, "urls": urls, "emails": emails}


class TsharkTool(ToolRunner):
    name = "tshark"

    async def run(self, mode: str = "capture", options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        options = options or {}
        pcap = self.run_dir / "out.pcap"
        if mode == "analyze":
            pcap = Path(options["pcap"])
        else:
            iface = options.get("interface") or self.config.defaults.tshark_interface
            duration = str(options.get("duration") or self.config.defaults.capture_duration)
            command = [self.config.tools.tshark, "-i", iface, "-a", f"duration:{duration}", "-w", str(pcap)]
            async for line in self.stream_process(command):
                yield line
        for command in (
            [self.config.tools.tshark, "-r", str(pcap), "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri", "-e", "http.authorization"],
            [self.config.tools.tshark, "-r", str(pcap), "-z", "io,phs", "-q"],
        ):
            async for line in self.stream_process(command):
                yield line
