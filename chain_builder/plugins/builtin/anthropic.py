"""Force Anthropic / Claude traffic through CHAIN (from ref configs)."""
from __future__ import annotations

from ..base import BuildContext, PluginContribution, RulePlugin

ANTHROPIC_DOMAINS = [
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    "claudemcpclient.com",
]

ANTHROPIC_EXACT = [
    "api.anthropic.com",
    "a-api.anthropic.com",
    "a-cdn.anthropic.com",
    "s-cdn.anthropic.com",
    "assets-proxy.anthropic.com",
    "mcp-proxy.anthropic.com",
    "console.anthropic.com",
    "www.anthropic.com",
    "platform.claude.com",
    "code.claude.com",
    "downloads.claude.ai",
    "bridge.claudeusercontent.com",
    "www.claudeusercontent.com",
    "servd-anthropic-website.b-cdn.net",
    "storage.googleapis.com",
    "raw.githubusercontent.com",
]

RELATED_SUFFIX = [
    "githubusercontent.com",
    "sentry.io",
    "datadoghq.com",
    "datadoghq.eu",
    "ddog-gov.com",
]


class AnthropicPlugin(RulePlugin):
    name = "anthropic"
    description = "Claude / Anthropic 及相关域名强制走第二跳（参考 ref）"
    forces_chain = True

    def contribute(self, ctx: BuildContext) -> PluginContribution:
        g = ctx.chain_group
        rules: list[str] = [
            f"PROCESS-NAME,claude.exe,{g}",
            f"PROCESS-NAME,Claude.exe,{g}",
            f"PROCESS-NAME-WILDCARD,*claude*,{g}",
            f"PROCESS-NAME-WILDCARD,*Claude*,{g}",
            f"PROCESS-PATH-REGEX,(?i).*claude.*,{g}",
            f"GEOSITE,ANTHROPIC,{g}",
        ]
        for d in ANTHROPIC_DOMAINS:
            rules.append(f"DOMAIN-SUFFIX,{d},{g}")
        for d in ANTHROPIC_EXACT:
            rules.append(f"DOMAIN,{d},{g}")
        rules.append(f"DOMAIN-SUFFIX,servd-anthropic-website.b-cdn.net,{g}")
        rules.extend(
            [
                f"DOMAIN-KEYWORD,anthropic,{g}",
                f"DOMAIN-KEYWORD,claude,{g}",
                f"DOMAIN-KEYWORD,cluade,{g}",
            ]
        )
        for d in RELATED_SUFFIX:
            rules.append(f"DOMAIN-SUFFIX,{d},{g}")
        rules.extend(
            [
                f"DOMAIN-KEYWORD,sentry,{g}",
                f"DOMAIN-KEYWORD,datadoghq,{g}",
                f"DOMAIN-KEYWORD,ddog,{g}",
            ]
        )

        dns_ns = [
            f"https://223.5.5.5/dns-query#{g}&skip-cert-verify=true",
            f"https://doh.pub/dns-query#{g}&skip-cert-verify=true",
        ]
        policy: dict[str, list[str]] = {
            "geosite:ANTHROPIC": list(dns_ns),
        }
        for d in ANTHROPIC_DOMAINS:
            policy[f"+.{d}"] = list(dns_ns)
        policy["servd-anthropic-website.b-cdn.net"] = list(dns_ns)
        for d in ("sentry.io", "datadoghq.com", "datadoghq.eu", "ddog-gov.com",
                  "githubusercontent.com"):
            policy[f"+.{d}"] = list(dns_ns)
        policy["raw.githubusercontent.com"] = list(dns_ns)
        policy["storage.googleapis.com"] = list(dns_ns)

        force = [f"+.{d}" for d in ANTHROPIC_DOMAINS]
        force += [
            "+.sentry.io",
            "+.datadoghq.com",
            "+.datadoghq.eu",
            "raw.githubusercontent.com",
            "storage.googleapis.com",
        ]
        return PluginContribution(
            rules=rules,
            dns_nameserver_policy=policy,
            sniffer_force_domains=force,
        )
