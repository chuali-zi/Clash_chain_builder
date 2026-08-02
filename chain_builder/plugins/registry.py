"""Plugin registry."""
from __future__ import annotations

from .base import RulePlugin
from .builtin.anthropic import AnthropicPlugin
from .builtin.full_chain import FullChainPlugin
from .builtin.openai import OpenAIPlugin


_REGISTRY: dict[str, RulePlugin] = {}


def _register(plugin: RulePlugin) -> None:
    _REGISTRY[plugin.name] = plugin


def load_builtins() -> None:
    if _REGISTRY:
        return
    for p in (FullChainPlugin(), AnthropicPlugin(), OpenAIPlugin()):
        _register(p)


def register_plugin(plugin: RulePlugin) -> None:
    load_builtins()
    _register(plugin)


def get_plugin(name: str) -> RulePlugin:
    load_builtins()
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY))
        raise KeyError(f"未知规则插件 '{name}'，可选: {known}")
    return _REGISTRY[name]


def list_plugins() -> list[RulePlugin]:
    load_builtins()
    return list(_REGISTRY.values())
