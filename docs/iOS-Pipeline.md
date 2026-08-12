# iOS Pipeline

## Flow

1. **Advisory** — scrape Apple HT201222 index → security content page for CVE
2. **Build pair** — AppleDB API resolves fixed version → `(pre_build, post_build)` + IPSW URLs
3. **Download** — `ipsw download` for canonical device (default `iPhone16,1`)
4. **Inventory** — `ipsw diff` → changed Mach-O list
5. **Rank** — component heuristic map + optional LLM rerank
6. **Extract** — `ipsw extract --dyld` for top dylib candidates
7. **RE** — Ghidra headless function diff + decompile
8. **Report** — LLM RCA → Chroma + `reports/` markdown

## v1 Limits

- Single device model
- Userspace dylibs only (no kernelcache deep-dive)
- Full IPSW pairs (~15–20 GB per CVE)

## Real-case command

```bash
peekaboo ios cve CVE-2024-23208 --device iPhone16,1
```

## Artifacts mode (skip download)

```bash
peekaboo artifacts CVE-2024-23208 --platform ios --pre ./pre/ --post ./post/
```
