"""Splunk SPL backend."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule


def _quote(value: str) -> str:
    return f'"{value}"' if (" " in value or value == "") else value


def _match(fm: FieldMatch) -> str:
    if fm.modifier == "eq":
        return f"{fm.field}={_quote(fm.value)}"
    if fm.modifier == "contains":
        return f"{fm.field}=*{fm.value}*"
    if fm.modifier == "startswith":
        return f"{fm.field}={fm.value}*"
    if fm.modifier == "endswith":
        return f"{fm.field}=*{fm.value}"
    if fm.modifier == "re":
        # SPL has no inline regex match operator -- `regex` is a separate
        # pipe stage. Emit the literal and flag it so the limitation is
        # obvious in the output rather than silently wrong.
        return f'{fm.field}="{fm.value}" /* regex: pipe through `| regex {fm.field}="{fm.value}"` */'
    raise ValueError(f"Unsupported modifier: {fm.modifier}")


def _render(node: Node, top: bool = False) -> str:
    if isinstance(node, FieldMatch):
        return _match(node)
    if isinstance(node, And):
        joined = " AND ".join(_render(c) for c in node.children)
        return joined if top else f"({joined})"
    if isinstance(node, Or):
        joined = " OR ".join(_render(c) for c in node.children)
        return joined if top else f"({joined})"
    if isinstance(node, Not):
        return f"NOT {_render(node.child)}"
    raise TypeError(f"Unknown node type: {type(node)!r}")


class SplunkBackend(Backend):
    name = "splunk"

    def render(self, rule: "SigmaRule") -> str:
        return _render(rule.ast, top=True)
