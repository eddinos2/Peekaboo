# Peekaboo

> Poly-platform CVE patch-diff root-cause analyzer — **iOS, Linux, Windows**.

Turn a CVE ID into a markdown report naming the patched binary, changed functions, pre/post decompilation, and an LLM-authored root-cause analysis.

Inspired by [akamai/patchdiff-ai](https://github.com/akamai/patchdiff-ai) (Apache-2.0). Peekaboo is a fresh implementation with iOS-first support, dual Ghidra/IDA RE backends, and OpenRouter multi-model routing.

## Features

- **Poly-platform CLI** — `peekaboo cve CVE-XXXX` auto-detects iOS / Linux / Windows
- **Confidence explainer** — deterministic scoring (component match, function diff, RE quality, LLM)
- **Diff Cinema** — HTML narrative export with confidence bars and patch story
- **Export pack** — `report.md`, `cinema.html`, `poc/`, `repro.sh`, `meta.json` per analysis
- **PoC blueprints** — senior-engineering reproduction plans (honest limitations, no fake exploits)
- **iOS pipeline** — Apple advisory → AppleDB → IPSW download → `ipsw diff` → dylib extract → RE → RCA
- **Linux pipeline** — Ubuntu USN enrichment + artifacts mode
- **Windows scaffold** — artifacts mode today; MSRC/KB gather when Windows host available
- **Dual RE backend** — Ghidra (default) + IDA/BinDiff (optional)
- **OpenRouter LLM** — route any model per pipeline stage
- **Artifacts mode** — skip download, point at local pre/post binary dirs
- **Report comparison** — diff two RCA reports for model eval

## Quick start

```bash
# Install (editable)
cd Peekaboo
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Bootstrap config
peekaboo init

# Set API key
export OPENROUTER__API_KEY=sk-or-...

# Validate prerequisites
peekaboo health-check
peekaboo ios health-check

# Analyze iOS CVE
peekaboo ios cve CVE-2024-23208 --device iPhone16,1

# Or auto-detect platform
peekaboo cve CVE-2024-23208

# Artifacts mode (no IPSW download)
peekaboo artifacts CVE-2024-23208 --platform ios --pre ./pre/ --post ./post/

# Export cinema + PoC pack from cache
peekaboo export --cve CVE-DEMO-0001
open ~/.local/share/peekaboo/reports/exports/*/cinema.html
```

## Prerequisites (macOS)

| Tool | Purpose |
|------|---------|
| Python 3.11+ | Runtime |
| [ipsw](https://github.com/blacktop/ipsw) | iOS IPSW download/extract/diff |
| Ghidra 11+ | Default RE backend |
| OpenRouter API key | LLM routing |
| ~20 GB disk | One iOS CVE (2 IPSWs) |
| IDA Pro (optional) | Second RE backend |

Config lives at `~/.local/share/peekaboo/config.json` (override with `PEEKABOO_HOME`).

## Architecture

```
CVE → enrich → gather → rank → RE diff → VR report → persist
```

See [docs/Architecture.md](docs/Architecture.md) for the full design.

## Platform status

| Platform | Auto-gather | Artifacts mode | RE |
|----------|-------------|----------------|-----|
| iOS | Yes (ipsw) | Yes | Ghidra/IDA |
| Linux | Needs Linux host | Yes | Ghidra/IDA |
| Windows | Needs Windows host | Yes | Ghidra/IDA |

## Real-case validation

Recommended first run:

```bash
peekaboo ios cve CVE-2024-23208 --device iPhone16,1
```

Reports saved to `~/.local/share/peekaboo/reports/` and Chroma cache.

## Development

```bash
pytest tests/
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Attribution

Architecture inspired by [akamai/patchdiff-ai](https://github.com/akamai/patchdiff-ai).
