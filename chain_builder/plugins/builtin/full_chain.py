"""All traffic through CHAIN (fail-closed). Simplest / safest basic preset."""
from __future__ import annotations

from ..base import BuildContext, PluginContribution, RulePlugin


class FullChainPlugin(RulePlugin):
    name = "full"
    description = "全部流量强制走第二跳链式代理（断连不漏 IP）"
    forces_chain = True

    def contribute(self, ctx: BuildContext) -> PluginContribution:
        # MATCH is added by builder; this plugin contributes nothing extra.
        # dns for general nameserver can optionally go through CHAIN — left to builder.
        return PluginContribution()
