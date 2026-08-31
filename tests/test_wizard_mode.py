"""Mode is chosen by flag, not an interactive prompt."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.cli import apply_mode_flags


def _ns(**kwargs):
    base = dict(preset=None, packs=None, full_chain=False)
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_no_flag_defaults_to_split():
    args = apply_mode_flags(_ns())
    assert args.preset == "default"


def test_full_chain_flag_selects_preset():
    args = apply_mode_flags(_ns(full_chain=True))
    assert args.preset == "full-chain"


def test_explicit_preset_kept_when_no_full_chain_flag():
    args = apply_mode_flags(_ns(preset="ai-minimal"))
    assert args.preset == "ai-minimal"


def test_full_chain_flag_overrides_other_preset():
    args = apply_mode_flags(_ns(preset="default", full_chain=True))
    assert args.preset == "full-chain"


def test_parser_accepts_full_chain_flag():
    from chain_builder.cli import build_parser

    args = apply_mode_flags(build_parser().parse_args(["--full-chain"]))
    assert args.full_chain is True
    assert args.preset == "full-chain"
