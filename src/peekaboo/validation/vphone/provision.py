"""VM provisioning helpers for Peekaboo + vphone-cli."""

from __future__ import annotations

import structlog

from peekaboo.config.settings import VPhoneSettings
from peekaboo.schemas import CveDetails
from peekaboo.validation.vphone.client import VPhoneClient

log = structlog.get_logger(__name__)


async def provision_cve_vms(
    client: VPhoneClient,
    details: CveDetails,
    settings: VPhoneSettings,
) -> tuple[str, str, list[str]]:
    """
    Ensure pre/post VMs exist for a CVE build pair.
    Returns (vm_pre_name, vm_post_name, notes).
    Full `vm create` is heavy — only runs when auto_provision=True.
    """
    notes: list[str] = []
    vm_pre = client.vm_name_for_build(details.cve, details.pre_build, role="pre")
    vm_post = client.vm_name_for_build(details.cve, details.post_build, role="post")

    if not settings.auto_provision:
        pre_ok = await client.vm_exists(vm_pre)
        post_ok = await client.vm_exists(vm_post)
        if not pre_ok or not post_ok:
            notes.append(
                f"VMs not provisioned (pre={pre_ok}, post={post_ok}). "
                f"Run: peekaboo vphone provision --cve {details.cve}"
            )
        return vm_pre, vm_post, notes

    variant = settings.variant
    for vm_name, build, version in (
        (vm_pre, details.pre_build, details.pre_version),
        (vm_post, details.post_build, details.fixed_version),
    ):
        if await client.vm_exists(vm_name):
            notes.append(f"VM exists: {vm_name}")
            continue
        log.info("vphone_vm_create", vm=vm_name, build=build, variant=variant)
        notes.append(f"Creating VM {vm_name} (build {build}, variant {variant}) — long-running")
        try:
            await client.run(
                "vm",
                "create",
                vm_name,
                "-V",
                variant,
                timeout=14400,
            )
            notes.append(f"Created VM: {vm_name}")
        except Exception as exc:
            notes.append(f"Failed to create {vm_name}: {exc}")

    return vm_pre, vm_post, notes
