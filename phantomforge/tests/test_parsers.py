import json
from pathlib import Path

from backend.mock_tools import NMAP_XML
from backend.tools.john_tool import parse_john_show
from backend.tools.nmap_tool import parse_nmap_xml
from backend.tools.sqlmap_tool import parse_sqlmap_output


def test_nmap_xml_parsing(tmp_path: Path):
    xml = tmp_path / "nmap.xml"
    xml.write_text(NMAP_XML, encoding="utf-8")
    parsed = parse_nmap_xml(xml)
    assert len(parsed["hosts"]) == 2
    assert "http://192.0.2.10:80/" in parsed["web_targets"]
    assert "https://192.0.2.20:443/" in parsed["web_targets"]
    assert "192.0.2.10" in parsed["hash_hosts"]


def test_sqlmap_json_parsing(tmp_path: Path):
    result = tmp_path / "results.json"
    result.write_text(json.dumps([{"url": "http://x/", "parameter": "id", "dbms": "MySQL"}]), encoding="utf-8")
    parsed = parse_sqlmap_output(result)
    assert parsed[0]["parameter"] == "id"
    assert parsed[0]["dbms"] == "MySQL"


def test_sqlmap_console_fallback(tmp_path: Path):
    result = tmp_path / "console.txt"
    result.write_text("back-end DBMS: PostgreSQL\nParameter: q (GET)\nType: boolean-based blind\nPayload: q=1 AND 1=1\n", encoding="utf-8")
    parsed = parse_sqlmap_output(result)
    assert parsed[-1]["parameter"] == "q (GET)"
    assert parsed[-1]["injection_type"] == "boolean-based blind"


def test_john_show_parsing():
    parsed = parse_john_show("alice:Password123\n0 password hashes cracked\n", "netntlmv2")
    assert parsed == [{"hash": "alice", "password": "Password123", "format": "netntlmv2"}]
