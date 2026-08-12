# Peekaboo Architecture

Peekaboo is a poly-platform CVE patch-diff analyzer. Given a CVE ID, it:

1. Resolves the platform (iOS / Linux / Windows)
2. Fetches advisory metadata and acquires pre/post patch artifacts
3. Ranks changed files as vulnerability candidates
4. Reverse-engineers changed functions (Ghidra or IDA)
5. Generates an LLM-authored root-cause analysis report

## Pipeline

```
CVE → enrich → gather → rank candidates → RE diff → VR report → persist
```

The pipeline is a **deterministic LangGraph state machine**. LLMs analyze and rank; they do not route.

## Layers

| Layer | Path | Role |
|-------|------|------|
| CLI | `cli/` | Click entry points, platform sub-groups |
| Config | `config/` | Pydantic settings, JSON + env |
| Core | `core/` | AppContext DI, orchestrator, logging |
| Platforms | `platforms/` | iOS, Linux, Windows plugins |
| Graphs | `graphs/` | LangGraph pipeline + agent nodes |
| RE | `re/` | Ghidra + IDA backend adapters |
| LLM | `llm/` | OpenRouter + direct provider registry |
| Persistence | `persistence/` | Chroma vector store + report cache |

## Platform Status

| Platform | Gather | RE | Notes |
|----------|--------|-----|-------|
| iOS | Full (ipsw) | Ghidra/IDA | macOS native |
| Linux | Artifacts mode | Ghidra/IDA | apt gather needs Linux host |
| Windows | Artifacts mode | Ghidra/IDA | MSRC/KB deferred |

Inspired by [akamai/patchdiff-ai](https://github.com/akamai/patchdiff-ai) (Apache-2.0).
