"""NVD CPE lookup."""

from __future__ import annotations

import httpx


def cpes_for(cve_id: str) -> list[str]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        resp = httpx.get(url, timeout=30.0, headers={"User-Agent": "Peekaboo/0.1"})
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    cpes: list[str] = []
    for item in data.get("vulnerabilities", []):
        for conf in item.get("cve", {}).get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        cpes.append(cpe)
    return cpes
