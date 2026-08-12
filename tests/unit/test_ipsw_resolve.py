from peekaboo.platforms.ios.ipsw_resolve import (
    is_stable_build,
    is_stable_ipsw_url,
    pre_version_candidates,
)


def test_pre_version_candidates_for_point_release():
    assert pre_version_candidates("26.6") == ["26.5.2", "26.5.1", "26.5"]


def test_stable_build_filter():
    assert is_stable_build("23G71")
    assert is_stable_build("23F84")
    assert not is_stable_build("23G5065a")


def test_stable_ipsw_url_filter():
    fcs = "https://updates.cdn-apple.com/2026SummerFCS/fullrestores/x.ipsw"
    seed = "https://updates.cdn-apple.com/2026SpringSeed/fullrestores/x.ipsw"
    assert is_stable_ipsw_url(fcs)
    assert not is_stable_ipsw_url(seed)
