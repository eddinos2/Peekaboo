"""Dynamic validation workflow via vphone-cli."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import structlog

from peekaboo.config.settings import VPhoneSettings
from peekaboo.core.app_context import AppContext
from peekaboo.schemas import CveDetails, PoCBlueprint, Report, ValidationResult
from peekaboo.validation.vphone.client import VPhoneClient, resolve_vphone_bin
from peekaboo.validation.vphone.payloads import build_validation_payload, guest_trigger_command
from peekaboo.validation.vphone.provision import provision_cve_vms

log = structlog.get_logger(__name__)

CRASH_PATTERNS = re.compile(
    r"(SIGSEGV|SIGBUS|EXC_BAD_ACCESS|panic|assertion failed|stack overflow|"
    r"killed|abort trap|segmentation fault)",
    re.I,
)


async def run_vphone_validation(
    ctx: AppContext,
    details: CveDetails | None,
    report: Report,
    poc: PoCBlueprint | None,
    *,
    work_dir: Path | None = None,
) -> ValidationResult:
    settings = ctx.settings.vphone
    if not settings.enabled or not settings.validate_on_pipeline:
        return ValidationResult(status="skipped", notes=["vphone validation disabled in config"])

    if details is None or details.platform != "ios":
        return ValidationResult(status="skipped", notes=["Not an iOS CVE"])

    try:
        client = VPhoneClient(settings)
        resolve_vphone_bin(settings.cli_path)
    except RuntimeError as exc:
        return ValidationResult(status="skipped", notes=[str(exc)])

    vm_pre, vm_post, prov_notes = await provision_cve_vms(client, details, settings)
    result = ValidationResult(
        vm_pre=vm_pre,
        vm_post=vm_post,
        pre_build=details.pre_build,
        post_build=details.post_build,
        notes=list(prov_notes),
    )

    pre_exists = await client.vm_exists(vm_pre)
    post_exists = await client.vm_exists(vm_post)
    if not pre_exists or not post_exists:
        result.status = "skipped"
        result.notes.append("Provision peekaboo VMs to enable dynamic validation")
        return result

    base = work_dir or (ctx.temp_dir / details.cve / "vphone")
    base.mkdir(parents=True, exist_ok=True)
    payload = build_validation_payload(base, details, poc)
    result.payload_path = str(payload)

    ctx.progress.info(f"vphone validation: {vm_pre} vs {vm_post}")

    try:
        pre_out = await _exercise_vm(client, vm_pre, payload, details, settings)
        post_out = await _exercise_vm(client, vm_post, payload, details, settings)
    except Exception as exc:
        log.warning("vphone_validation_failed", error=str(exc))
        result.status = "error"
        result.notes.append(str(exc))
        result.log_excerpt = str(exc)[:2000]
        return result

    result.pre_crash_detected = _detect_crash(pre_out)
    result.post_crash_detected = _detect_crash(post_out)
    result.asymmetric = result.pre_crash_detected and not result.post_crash_detected
    result.log_excerpt = (pre_out + "\n---\n" + post_out)[:4000]

    if result.asymmetric:
        result.status = "passed"
        result.confidence_boost = 0.15
        result.notes.append("Asymmetric crash: pre vulnerable, post stable")
    elif result.pre_crash_detected and result.post_crash_detected:
        result.status = "failed"
        result.notes.append("Crash on both builds — payload not patch-specific")
    else:
        result.status = "skipped"
        result.notes.append("No crash asymmetry detected (stub payload or VM limits)")

    return result


async def _exercise_vm(
    client: VPhoneClient,
    vm_name: str,
    payload: Path,
    details: CveDetails,
    settings: VPhoneSettings,
) -> str:
    await client.launch_vm(vm_name)
    await asyncio.sleep(8)
    remote = f"/tmp/{payload.name}"
    try:
        await client.scp_to_guest(payload, remote)
        cmd = guest_trigger_command(payload.name, details)
        _, stdout, stderr = await client.ssh_exec(cmd, timeout=60.0)
        output = stdout + stderr
    finally:
        await client.stop_vm(vm_name)
    return output


def _detect_crash(output: str) -> bool:
    return bool(CRASH_PATTERNS.search(output))


async def vphone_status(settings: VPhoneSettings) -> tuple[bool, list[str], list[str]]:
    """Return (ok, issues, info lines)."""
    info: list[str] = []
    try:
        client = VPhoneClient(settings)
        info.append(f"binary: {client.bin}")
        info.append(f"library: {client.library}")
    except RuntimeError as exc:
        return False, [str(exc)], info

    ok, issues = await client.health_check()
    try:
        vms = await client.list_vms()
        peekaboo_vms = [v.name for v in vms if v.name.startswith(settings.vm_prefix)]
        info.append(f"VMs: {len(vms)} total, {len(peekaboo_vms)} peekaboo")
        for name in peekaboo_vms[:10]:
            info.append(f"  - {name}")
    except Exception as exc:
        issues.append(f"vm list: {exc}")
        ok = False

    cache = client.library / "ipsws"
    if cache.exists():
        ipsw_count = len(list(cache.rglob("*.ipsw")))
        info.append(f"IPSW cache: {ipsw_count} files under {cache}")
    else:
        info.append("IPSW cache: empty (created on first vphone fw prepare)")

    return ok, issues, info
