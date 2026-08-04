from pathlib import Path

from backend.config import load_config


def test_config_loading(tmp_path: Path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("mock: true\nconcurrency_limit: 3\ntools:\n  nmap: /tmp/nmap\n", encoding="utf-8")
    cfg = load_config(cfg_path)
    assert cfg.mock is True
    assert cfg.concurrency_limit == 3
    assert cfg.tools.nmap == "/tmp/nmap"
    assert cfg.tools.sqlmap == "/usr/bin/sqlmap"
