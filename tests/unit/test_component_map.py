"""Unit tests for component map."""

from peekaboo.platforms.ios.component_map import load_component_map, rank_changed_files


def test_load_component_map():
    rules = load_component_map()
    assert "WebKit" in rules
    assert "libxpc" in rules


def test_rank_changed_files():
    rules = load_component_map()
    changed = ["System/Library/Frameworks/WebKit.framework/WebKit", "random.dylib"]
    ranked = rank_changed_files(changed, "WebKit", rules)
    assert ranked[0][0] == changed[0]
    assert ranked[0][1] > ranked[1][1]
