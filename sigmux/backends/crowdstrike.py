"""CrowdStrike Falcon LogScale (LQL) backend.

LogScale's query language reads a lot like Splunk's SPL for field matching
(bare `field = value` terms, wildcards embedded directly in the compared
string) but uses lowercase boolean keywords and `/pattern/` regex literals
instead of a separate `regex` pipe stage.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule


def _term(value: str) -> str:
    return f'"{value}"' if (" " in value or value == "") else value


def _match(fm: FieldMatch) -> str:
    if fm.modifier == "eq":
        return f"{fm.field} = {_term(fm.value)}"
    if fm.modifier == "contains":
        return f"{fm.field} = {_term(f'*{fm.value}*')}"
    if fm.modifier == "startswith":
        return f"{fm.field} = {_term(f'{fm.value}*')}"
    if fm.modifier == "endswith":
        return f"{fm.field} = {_term(f'*{fm.value}')}"
    if fm.modifier == "re":
        return f"{fm.field} = /{fm.value}/"
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


class CrowdStrikeBackend(Backend):
    name = "crowdstrike"

    def render(self, rule: "SigmaRule") -> str:
        return _render(rule.ast, top=True)
