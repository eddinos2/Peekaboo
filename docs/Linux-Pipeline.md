# Linux Pipeline

## Flow (Ubuntu 24.04)

1. **Advisory** — Ubuntu CVE page + USN link
2. **Gather** — automatic `apt-get source` requires Linux host
3. **Artifacts mode** — provide pre/post `.so` directories on macOS
4. **RE + Report** — shared pipeline

## Command

```bash
peekaboo linux cve CVE-2024-XXXX --pre ./pre_libs/ --post ./post_libs/
```

## Deferred

- Docker-based apt gather automation
- Debian DSA native scraper
