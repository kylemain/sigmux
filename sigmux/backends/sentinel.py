"""Microsoft Sentinel (Kusto / KQL) backend."""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional, Tuple

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule

# Best-effort logsource -> Sentinel/Defender table mapping. Covers the most
# common Sigma logsource categories/products out of the box; override per
# your own table layout for anything more specific.
_TABLE_MAP: Dict[Tuple[Optional[str], Optional[str]], str] = {
    ("process_creation", None): "DeviceProcessEvents",
    ("network_connection", None): "DeviceNetworkEvents",
    ("file_event", None): "DeviceFileEvents",
    ("registry_event", None): "DeviceRegistryEvents",
    (None, "windows"): "SecurityEvent",
    (None, "azure"): "AzureActivity",
    (None, "aws"): "AWSCloudTrail",
}
_DEFAULT_TABLE = "SecurityEvent"


def _table_for(logsource: Dict[str, str]) -> str:
    category = logsource.get("category")
    product = logsource.get("product")
    return (
        _TABLE_MAP.get((category, None))
        or _TABLE_MAP.get((None, product))
        or _DEFAULT_TABLE
    )


def _quote(value: str) -> str:
    return value.replace('"', '\\"')


def _match(fm: FieldMatch) -> str:
    v = _quote(fm.value)
    if fm.modifier == "eq":
        return f'{fm.field} == "{v}"'
    if fm.modifier == "contains":
        return f'{fm.field} has "{v}"'
    if fm.modifier == "startswith":
        return f'{fm.field} startswith "{v}"'
    if fm.modifier == "endswith":
        return f'{fm.field} endswith "{v}"'
    if fm.modifier == "re":
        return f'{fm.field} matches regex "{v}"'
    raise ValueError(f"Unsupported modifier: {fm.modifier}")


def _render(node: Node, top: bool = False) -> str:
    if isinstance(node, FieldMatch):
        return _match(node)
    if isinstance(node, And):
        joined = " and ".join(_render(c) for c in node.children)
        return joined if top else f"({joined})"
    if isinstance(node, Or):
        joined = " or ".join(_render(c) for c in node.children)
        return joined if top else f"({joined})"
    if isinstance(node, Not):
        return f"not ({_render(node.child, top=True)})"
    raise TypeError(f"Unknown node type: {type(node)!r}")


class SentinelBackend(Backend):
    name = "sentinel"

    def render(self, rule: "SigmaRule") -> str:
        table = _table_for(rule.logsource)
        return f"{table}\n| where {_render(rule.ast, top=True)}"
