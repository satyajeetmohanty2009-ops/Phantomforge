from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, AsyncIterator

from .base import ToolRunner


WEB_PORTS = {80, 443, 8080, 8443}
HASH_PORTS = {88, 139, 445}


def parse_nmap_xml(path: str | Path) -> dict[str, Any]:
    root = ET.parse(path).getroot()
    hosts: list[dict[str, Any]] = []
    web_targets: list[str] = []
    hash_hosts: list[str] = []
    scripts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "unknown"
        ports: list[dict[str, Any]] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = int(port.get("portid", "0"))
            service = port.find("service")
            svc = {
                "port": port_id,
                "protocol": port.get("protocol", "tcp"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
            for script in port.findall("script"):
                scripts.append({"host": address, "port": port_id, "id": script.get("id", ""), "output": script.get("output", "")})
            ports.append(svc)
            if port_id in WEB_PORTS:
                scheme = "https" if port_id in {443, 8443} else "http"
                web_targets.append(f"{scheme}://{address}:{port_id}/")
            if port_id in HASH_PORTS:
                hash_hosts.append(address)
        hosts.append({"address": address, "ports": ports})
    return {"hosts": hosts, "web_targets": sorted(set(web_targets)), "hash_hosts": sorted(set(hash_hosts)), "scripts": scripts}


class NmapTool(ToolRunner):
    name = "nmap"

    async def run(self, target: str, options: dict[str, Any] | None = None) -> AsyncIterator[str]:
        options = options or {}
        xml_path = self.run_dir / "nmap.xml"
        flags = options.get("flags") or self.config.defaults.nmap_flags
        timing = options.get("timing") or self.config.defaults.nmap_timing
        parts = [self.config.tools.nmap, *flags.split(), *timing.split()]
        if options.get("vuln_scripts") or self.config.defaults.nmap_vuln_scripts:
            parts += ["--script", "vuln"]
        command = [*parts, "-oX", str(xml_path), target]
        async for line in self.stream_process(command):
            yield line
