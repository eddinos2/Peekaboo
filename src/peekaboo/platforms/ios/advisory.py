"""Apple security advisory scraper."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx
from bs4 import BeautifulSoup


HT201222 = "https://support.apple.com/en-us/HT201222"


@dataclass
class AdvisoryEntry:
    cve: str
    component: str
    impact: str
    description: str
    fixed_version: str
    advisory_url: str


async def find_advisory_for_cve(cve_id: str) -> AdvisoryEntry | None:
    cve_upper = cve_id.upper()
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        index_resp = await client.get(HT201222)
        index_resp.raise_for_status()
        index_soup = BeautifulSoup(index_resp.text, "html.parser")

        advisory_links: list[tuple[str, str]] = []
        for a in index_soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(strip=True)
            if "security content" in text.lower() or re.search(r"/\d{5,6}$", href):
                url = href if href.startswith("http") else f"https://support.apple.com{href}"
                advisory_links.append((text, url))

        for _title, url in advisory_links[:80]:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                entry = _parse_advisory_page(resp.text, url, cve_upper)
                if entry:
                    return entry
            except Exception:
                continue
    return None


def _parse_advisory_page(html: str, url: str, cve_id: str) -> AdvisoryEntry | None:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)
    if cve_id not in text:
        return None

    version_match = re.search(r"iOS\s+([\d.]+)", text)
    fixed_version = version_match.group(1) if version_match else ""

    component = impact = description = ""
    blocks = re.split(r"(?=(?:Available for:|Impact:|Description:|CVE-))", text)
    for block in blocks:
        if cve_id not in block:
            continue
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        for ln in lines:
            if ln.startswith("CVE-"):
                continue
            if ln in ("Impact:", "Description:", "Available for:"):
                continue
            if re.match(r"^[A-Za-z][A-Za-z0-9\s\.\-_]+$", ln) and len(ln) < 40:
                component = ln
                break
        imp = re.search(r"Impact:\s*(.+?)(?:Description:|CVE|$)", block, re.S)
        if imp:
            impact = imp.group(1).strip()
        desc = re.search(r"Description:\s*(.+?)(?:CVE|$)", block, re.S)
        if desc:
            description = desc.group(1).strip()
        break

    return AdvisoryEntry(
        cve=cve_id,
        component=component or "Unknown",
        impact=impact,
        description=description,
        fixed_version=fixed_version,
        advisory_url=url,
    )
