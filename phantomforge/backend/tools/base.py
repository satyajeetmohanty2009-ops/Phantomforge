from __future__ import annotations

import asyncio
import os
import shlex
import signal
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, AsyncIterator


class ToolError(RuntimeError):
    pass


class ToolRunner(ABC):
    name: str

    def __init__(self, config: Any, run_dir: Path):
        self.config = config
        self.run_dir = run_dir
        self.process: asyncio.subprocess.Process | None = None

    async def stream_process(self, command: list[str], cwd: Path | None = None) -> AsyncIterator[str]:
        executable = command[0]
        if not Path(executable).exists() and "/" in executable:
            raise ToolError(f"Missing {self.name} at {executable}; update {self.config.config_path}")
        yield f"$ {shlex.join(command)}"
        self.process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd or self.run_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=(os.name != "nt"),
        )
        assert self.process.stdout
        async for raw in self.process.stdout:
            yield raw.decode(errors="replace").rstrip()
        code = await self.process.wait()
        yield f"[exit {code}]"
        if code != 0:
            raise ToolError(f"{self.name} exited with {code}")

    async def stop(self) -> None:
        if not self.process or self.process.returncode is not None:
            return
        if os.name == "nt":
            self.process.terminate()
        else:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        try:
            await asyncio.wait_for(self.process.wait(), timeout=5)
        except asyncio.TimeoutError:
            self.process.kill()

    @abstractmethod
    async def run(self, *args: Any, **kwargs: Any) -> AsyncIterator[str]:
        yield ""
