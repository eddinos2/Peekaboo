"""vphone-cli subprocess wrapper."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from peekaboo.config.settings import VPhoneSettings
from peekaboo.tools.process import ToolError, run


def resolve_vphone_bin(configured: str | None) -> str:
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("vphone-cli")
    if found:
        return found
    app_bin = Path.home() / ".vphone" / "build" / "vphone-cli.app" / "Contents" / "MacOS" / "vphone-cli"
    if app_bin.exists():
        return str(app_bin)
    raise RuntimeError(
        "vphone-cli not found — run: peekaboo vphone setup "
        "(see https://github.com/Lakr233/vphone-cli)"
    )


def vphone_library_root(settings: VPhoneSettings) -> Path:
    if settings.library_root:
        return Path(settings.library_root).expanduser()
    env = Path.home() / ".vphone"
    return env


def vphone_ipsw_cache_dir(settings: VPhoneSettings) -> Path:
    return vphone_library_root(settings) / "ipsws"


@dataclass
class VPhoneVmInfo:
    name: str
    state: str = "unknown"
    raw: dict | None = None


class VPhoneClient:
    def __init__(self, settings: VPhoneSettings) -> None:
        self.settings = settings
        self.bin = resolve_vphone_bin(settings.cli_path)
        self.library = vphone_library_root(settings)

    async def run(self, *args: str, timeout: float = 3600.0) -> str:
        result = await run(self.bin, *args, timeout=timeout)
        return result.stdout

    async def health_check(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        try:
            resolve_vphone_bin(self.settings.cli_path)
        except RuntimeError as exc:
            return False, [str(exc)]
        try:
            await self.run("--help", timeout=30.0)
        except ToolError as exc:
            issues.append(f"vphone-cli failed: {exc}")
        if not self.library.exists():
            issues.append(f"vphone library missing: {self.library} (run peekaboo vphone setup)")
        return len(issues) == 0, issues

    async def list_vms(self) -> list[VPhoneVmInfo]:
        try:
            out = await self.run("vm", "list", "--json", timeout=60.0)
        except ToolError:
            out = await self.run("vm", "list", timeout=60.0)
            return [VPhoneVmInfo(name=line.strip()) for line in out.splitlines() if line.strip()]
        data = json.loads(out)
        items = data if isinstance(data, list) else data.get("vms") or data.get("items") or []
        vms: list[VPhoneVmInfo] = []
        for item in items:
            if isinstance(item, str):
                vms.append(VPhoneVmInfo(name=item))
            elif isinstance(item, dict):
                name = item.get("name") or item.get("id") or ""
                vms.append(VPhoneVmInfo(name=name, state=str(item.get("state", "")), raw=item))
        return vms

    async def vm_exists(self, name: str) -> bool:
        return any(v.name == name for v in await self.list_vms())

    def vm_name_for_build(self, cve: str, build: str, *, role: str) -> str:
        slug = cve.lower().replace("-", "")
        return f"{self.settings.vm_prefix}-{slug}-{role}-{build.lower()}"

    async def launch_vm(self, name: str, *, dfu: bool = False) -> None:
        args = ["vm", "launch", name]
        if dfu:
            args.append("--dfu")
        await self.run(*args, timeout=120.0)

    async def stop_vm(self, name: str) -> None:
        try:
            await self.run("vm", "stop", name, timeout=120.0)
        except ToolError:
            pass

    async def ssh_exec(
        self,
        command: str,
        *,
        port: int | None = None,
        user: str | None = None,
        timeout: float = 120.0,
    ) -> tuple[int, str, str]:
        """Run command on guest via sshpass + ssh (jb variant)."""
        port = port or self.settings.ssh_port
        user = user or self.settings.ssh_user
        password = self.settings.ssh_password
        sshpass = shutil.which("sshpass")
        if not sshpass:
            raise RuntimeError("sshpass not found — install via: brew install sshpass")
        argv = [
            sshpass,
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            str(port),
            f"{user}@127.0.0.1",
            command,
        ]
        proc_argv = [str(a) for a in argv]
        result = await run(*proc_argv, timeout=timeout)
        return 0, result.stdout, result.stderr

    async def scp_to_guest(
        self,
        local_path: Path,
        remote_path: str,
        *,
        port: int | None = None,
        user: str | None = None,
    ) -> None:
        port = port or self.settings.ssh_port
        user = user or self.settings.ssh_user
        password = self.settings.ssh_password
        sshpass = shutil.which("sshpass")
        if not sshpass:
            raise RuntimeError("sshpass not found")
        await run(
            sshpass,
            "-p",
            password,
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(port),
            str(local_path),
            f"{user}@127.0.0.1:{remote_path}",
            timeout=300.0,
        )
