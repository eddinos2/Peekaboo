"""Component → dylib heuristic engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from peekaboo.core.paths import resource_path


@dataclass
class ComponentRule:
    name: str
    priority: str
    patterns: list[str]
    auto_re: bool = True


def load_component_map(path: Path | None = None) -> dict[str, ComponentRule]:
    map_path = path or resource_path("ios_component_map.yaml")
    if not map_path.exists():
        return {}
    raw = yaml.safe_load(map_path.read_text(encoding="utf-8")) or {}
    rules: dict[str, ComponentRule] = {}
    for name, cfg in raw.items():
        rules[name] = ComponentRule(
            name=name,
            priority=cfg.get("priority", "medium"),
            patterns=cfg.get("patterns", []),
            auto_re=cfg.get("auto_re", True),
        )
    return rules


def score_file_for_component(file_path: str, component: str, rules: dict[str, ComponentRule]) -> float:
    component_key = _match_component_key(component, rules)
    if not component_key:
        return 0.1
    rule = rules[component_key]
    lower = file_path.lower()
    for pattern in rule.patterns:
        pat = pattern.lower().strip("*")
        if pat in lower or lower.endswith(pat):
            return 1.0 if rule.priority in ("high", "kernel") else 0.7
    return 0.2


def _match_component_key(component: str, rules: dict[str, ComponentRule]) -> str | None:
    comp_lower = component.lower()
    for name in rules:
        if name.lower() in comp_lower or comp_lower in name.lower():
            return name
    return None


def rank_changed_files(
    changed_files: list[str],
    component: str,
    rules: dict[str, ComponentRule] | None = None,
) -> list[tuple[str, float, bool]]:
    rules = rules or load_component_map()
    scored: list[tuple[str, float, bool]] = []
    component_key = _match_component_key(component, rules)
    auto_re = rules[component_key].auto_re if component_key else True
    for f in changed_files:
        score = score_file_for_component(f, component, rules)
        scored.append((f, score, auto_re))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored
