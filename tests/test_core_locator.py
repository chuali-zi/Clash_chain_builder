"""Unit tests for mihomo core discovery (no real core required)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder import core_locator as cl

EXT = ".exe" if cl.IS_WIN else ""


def _touch_exe(directory: Path, name: str) -> Path:
    p = directory / f"{name}{EXT}"
    p.write_text("", encoding="utf-8")
    if not cl.IS_WIN:
        p.chmod(0o755)
    return p


def test_core_stem_matching():
    good = [
        "mihomo",
        "mihomo-alpha",
        "verge-mihomo",
        "verge-mihomo-alpha",
        "clash-meta",
        "Clash.Meta-windows-amd64",
        "mihomo-windows-amd64-v1.19.1",
        "clash",
    ]
    bad = [
        "clash-verge",
        "Clash Verge",
        "clash-verge-service",
        "Clash for Windows",
        "FlClash",
        "notepad",
    ]
    for name in good:
        assert cl.CORE_STEM_RE.match(name), name
    for name in bad:
        assert not cl.CORE_STEM_RE.match(name), name


def test_scan_dir_prefers_stable_build(tmp_path=None):
    import tempfile

    root = Path(tmp_path or tempfile.mkdtemp(prefix="core-scan-"))
    nested = root / "resources"
    nested.mkdir(parents=True, exist_ok=True)
    _touch_exe(root, "verge-mihomo-alpha")
    stable = _touch_exe(root, "verge-mihomo")
    _touch_exe(root, "clash-verge")
    _touch_exe(nested, "mihomo-windows-amd64-v1.19.1")

    hits = cl._scan_dir(root, depth=2)
    names = [Path(h).name for h in hits]
    assert Path(hits[0]) == stable
    assert f"clash-verge{EXT}" not in names
    assert f"mihomo-windows-amd64-v1.19.1{EXT}" in names


def test_env_var_file_and_dir():
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="core-env-"))
    exe = _touch_exe(root, "mihomo")

    old = {k: os.environ.get(k) for k in cl.ENV_BIN_VARS + cl.ENV_DIR_VARS}
    try:
        for k in old:
            os.environ.pop(k, None)
        os.environ["MIHOMO_BIN"] = f'"{exe}"'
        paths = [c.path for c in cl._env_candidates()]
        assert str(exe) in paths

        os.environ["MIHOMO_BIN"] = str(root)
        paths = [c.path for c in cl._env_candidates()]
        assert str(exe) in paths

        os.environ.pop("MIHOMO_BIN")
        os.environ["CLASH_HOME"] = str(root)
        paths = [c.path for c in cl._env_candidates()]
        assert str(exe) in paths
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_candidates_are_unique():
    seen = [c.path for c in cl.iter_candidates()]
    normalized = [os.path.normcase(os.path.abspath(p)) for p in seen]
    assert len(normalized) == len(set(normalized))


def test_searched_locations_non_empty():
    assert len(cl.searched_locations()) >= 4


if __name__ == "__main__":
    test_core_stem_matching()
    test_scan_dir_prefers_stable_build()
    test_env_var_file_and_dir()
    test_candidates_are_unique()
    test_searched_locations_non_empty()
    print("all ok")
