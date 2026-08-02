"""Plugin interface for rule packs / customizations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BuildContext:
    hop1_name: str
    hop2_name: str
    chain_group: str = "CHAIN"
    hop1_group: str = "HOP1"
    exit_ip: str | None = None


@dataclass
class PluginContribution:
    rules: list[str] = field(default_factory=list)
    # inserted before MATCH; for forced-chain domains
    dns_nameserver_policy: dict[str, list[str]] = field(default_factory=dict)
    sniffer_force_domains: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class RulePlugin:
    """Base class for rule plugins.

    Built-in and user plugins implement contribute().
    Future plugins can drop into plugins/ or be registered via entry points.
    """

    name: str = "base"
    description: str = ""
    # If True, traffic matched by this plugin MUST go through CHAIN (no-leak)
    forces_chain: bool = True

    def contribute(self, ctx: BuildContext) -> PluginContribution:
        raise NotImplementedError
