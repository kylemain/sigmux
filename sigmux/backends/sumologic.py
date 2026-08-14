"""Sumo Logic search query backend.

Sumo Logic's search syntax is deliberately close to Splunk's SPL for field
filtering: bare `field=value` terms with native wildcard support, joined
with uppercase `AND`/`OR`/`NOT`. It has no inline regex match operator
either -- regex filtering needs a `| where field matches /pattern/` pipe
stage, so (like the Splunk backend's `re` handling) that case emits a
flagged placeholder rather than silently wrong syntax.
"""
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
        return f'{fm.field}="{fm.value}" /* regex: pipe through `| where {fm.field} matches /{fm.value}/` */'
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


class SumoLogicBackend(Backend):
    name = "sumologic"

    def render(self, rule: "SigmaRule") -> str:
        return _render(rule.ast, top=True)
