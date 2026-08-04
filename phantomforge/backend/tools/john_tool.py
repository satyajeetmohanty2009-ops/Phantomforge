from __future__ import annotations

import gzip
import shutil
from pathlib import Path
from typing import Any, AsyncIterator

from .base import ToolRunner


def parse_john_show(text: str, fmt: str = "unknown") -> list[dict[str, str]]:
    cracked: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line or line.startswith(("0 password", "Loaded ", "No password")):
            continue
        if ":" in line:
            left, password, *_ = line.split(":")
            cracked.append({"hash": left, "password": password, "format": fmt})
    return cracked


class JohnTool(ToolRunner):
    name = "john"

    def _wordlist(self) -> str:
        wordlist = Path(self.config.defaults.john_wordlist)
        if wordlist.suffix == ".gz" and wordlist.exists():
            dest = self.run_dir / wordlist.stem
            if not dest.exists():
                with gzip.open(wordlist, "rb") as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
            return str(dest)
        return str(wordlist)

    async def run(self, hash_files: list[str], fmt: str = "nt") -> AsyncIterator[str]:
        pot = self.run_dir / "john.pot"
        wordlist = self._wordlist()
        for hash_file in hash_files:
            command = [self.config.tools.john, f"--format={fmt}", f"--wordlist={wordlist}", f"--pot={pot}", hash_file]
            async for line in self.stream_process(command):
                yield line
            show = [self.config.tools.john, f"--format={fmt}", f"--pot={pot}", "--show", hash_file]
            async for line in self.stream_process(show):
                yield line
