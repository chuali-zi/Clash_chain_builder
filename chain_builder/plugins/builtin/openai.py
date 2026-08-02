"""Force OpenAI / ChatGPT traffic through CHAIN."""
from __future__ import annotations

from ..base import BuildContext, PluginContribution, RulePlugin

OPENAI_SUFFIX = [
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "openaiapi-site.azureedge.net",
]


class OpenAIPlugin(RulePlugin):
    name = "openai"
    description = "OpenAI / ChatGPT 域名强制走第二跳"
    forces_chain = True

    def contribute(self, ctx: BuildContext) -> PluginContribution:
        g = ctx.chain_group
        rules = [f"DOMAIN-SUFFIX,{d},{g}" for d in OPENAI_SUFFIX]
        rules += [
            f"DOMAIN-KEYWORD,openai,{g}",
            f"DOMAIN-KEYWORD,chatgpt,{g}",
        ]
        dns_ns = [
            f"https://223.5.5.5/dns-query#{g}&skip-cert-verify=true",
            f"https://doh.pub/dns-query#{g}&skip-cert-verify=true",
        ]
        policy = {f"+.{d}": list(dns_ns) for d in OPENAI_SUFFIX if not d.endswith("azureedge.net")}
        policy["+.openaiapi-site.azureedge.net"] = list(dns_ns)
        force = [f"+.{d}" for d in ("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com")]
        return PluginContribution(
            rules=rules,
            dns_nameserver_policy=policy,
            sniffer_force_domains=force,
        )
