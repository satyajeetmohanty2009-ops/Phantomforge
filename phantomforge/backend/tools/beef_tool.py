from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, AsyncIterator

import httpx

from .base import ToolRunner


class BeefTool(ToolRunner):
    name = "beef"

    def __init__(self, config: Any, run_dir: Path):
        super().__init__(config, run_dir)
        self.token: str | None = None
        self.started_by_app = False

    async def login(self) -> str:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{self.config.beef.base_url}/api/admin/login",
                json={"username": self.config.beef.username, "password": self.config.beef.password},
            )
            resp.raise_for_status()
            self.token = resp.json().get("token")
            if not self.token:
                raise RuntimeError("BeEF login did not return a token")
            return self.token

    async def sessions(self) -> list[dict[str, Any]]:
        if not self.token:
            await self.login()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.config.beef.base_url}/api/sessions", params={"token": self.token})
            resp.raise_for_status()
            data = resp.json()
            return data.get("hooked-browsers", {}).get("online", []) if isinstance(data, dict) else []

    async def run(self, hook_url: str | None = None, poll_seconds: int = 8) -> AsyncIterator[str]:
        hook = hook_url or self.config.beef.hook_url
        if self.config.beef.beef_start_on_run:
            self.started_by_app = True
            self.process = await asyncio.create_subprocess_exec(
                self.config.tools.beef,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(self.run_dir),
            )
            yield f"Started BeEF from {self.config.tools.beef}"
            await asyncio.sleep(3)
        yield f"Hook URL: {hook}"
        await self.login()
        for _ in range(poll_seconds):
            sessions = await self.sessions()
            yield f"Hooked browsers online: {len(sessions)}"
            await asyncio.sleep(1)
