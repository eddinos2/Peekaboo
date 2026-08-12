"""Ubuntu USN advisory scraper."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx
from bs4 import BeautifulSoup


@dataclass
class UbuntuAdvisory:
    cve: str
    usn_id: str
    description: str
    packages: list[str]
    fixed_version: str
    url: str


async def find_ubuntu_advisory(cve_id: str) -> UbuntuAdvisory | None:
    cve_upper = cve_id.upper()
    search_url = f"https://ubuntu.com/security/cves/{cve_upper.lower()}"
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        resp = await client.get(search_url)
        if resp.status_code != 200:
            return None
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text("\n", strip=True)
        if cve_upper not in text:
            return None

        usn_links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/security/notices/USN-" in href:
                usn_links.append(href if href.startswith("http") else f"https://ubuntu.com{href}")

        packages: list[str] = []
        for line in text.splitlines():
            if "package" in line.lower() or ".so" in line:
                packages.append(line.strip())

        usn_id = "unknown"
        if usn_links:
            m = re.search(r"USN-\d+-\d+", usn_links[0])
            if m:
                usn_id = m.group(0)

        return UbuntuAdvisory(
            cve=cve_upper,
            usn_id=usn_id,
            description=text[:500],
            packages=packages[:20],
            fixed_version="",
            url=search_url,
        )
