"""Output filename: mode suffix + --name, without silent overwrite."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.cli import DEFAULT_OUT_DIR, apply_mode_flags, build_parser, resolve_output_path
from chain_builder.geo import output_filename, sanitize_output_name


def _ns(**kwargs):
    base = dict(out=None, out_dir=None, name=None, preset="default", full_chain=False)
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_split_default_filename_unchanged():
    assert output_filename("167.253.38.151", "US-California") == "167.253.38.151_US-California.yaml"


def test_full_chain_filename_adds_suffix():
    assert (
        output_filename("167.253.38.151", "US-California", suffix="full-chain")
        == "167.253.38.151_US-California_full-chain.yaml"
    )


def test_empty_suffix_same_as_none():
    assert output_filename("1.2.3.4", "US", suffix="") == "1.2.3.4_US.yaml"


def test_sanitize_name_adds_yaml():
    assert sanitize_output_name("my-full") == "my-full.yaml"


def test_sanitize_name_keeps_yaml_suffix():
    assert sanitize_output_name("my-full.yaml") == "my-full.yaml"


def test_sanitize_name_strips_unsafe_chars():
    assert sanitize_output_name("foo/bar baz") == "foo-bar-baz.yaml"


def test_resolve_prefers_out_over_name():
    path = resolve_output_path(
        _ns(out="C:/tmp/explicit.yaml", name="ignored"),
        "1.2.3.4",
        "US",
    )
    assert path == Path("C:/tmp/explicit.yaml")


def test_resolve_name_uses_out_dir():
    path = resolve_output_path(_ns(name="my-full", out_dir="D:/cfgs"), "1.2.3.4", "US")
    assert path == Path("D:/cfgs") / "my-full.yaml"


def test_resolve_full_chain_default_does_not_collide_with_split():
    split = resolve_output_path(_ns(preset="default"), "1.2.3.4", "US")
    full = resolve_output_path(_ns(preset="full-chain"), "1.2.3.4", "US")
    assert split == DEFAULT_OUT_DIR / "1.2.3.4_US.yaml"
    assert full == DEFAULT_OUT_DIR / "1.2.3.4_US_full-chain.yaml"
    assert split != full


def test_parser_accepts_name_flag():
    args = apply_mode_flags(build_parser().parse_args(["--full-chain", "--name", "my-full"]))
    assert args.name == "my-full"
    path = resolve_output_path(args, "1.2.3.4", "US")
    assert path == DEFAULT_OUT_DIR / "my-full.yaml"
