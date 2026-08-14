"""IBM QRadar (Ariel Query Language / AQL) backend.

AQL is SQL-flavored: a `SELECT ... FROM events WHERE ...` statement rather
than a bare boolean expression. Field names are emitted as the raw Sigma
field names -- mapping those onto QRadar's actual AQL property names (or a
custom QID map) is deployment-specific and out of scope here, same as the
Sentinel backend's logsource-to-table mapping. Time-window filtering
(`LAST <n> <unit>`) is likewise left for the caller to add; Sigma's
`condition` block doesn't carry a timeframe for the non-aggregate rules this
project supports.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _match(fm: FieldMatch) -> str:
    if fm.modifier == "eq":
        return f"{fm.field} = {_quote(fm.value)}"
    if fm.modifier == "contains":
        return f"{fm.field} LIKE {_quote(f'%{fm.value}%')}"
    if fm.modifier == "startswith":
        return f"{fm.field} LIKE {_quote(f'{fm.value}%')}"
    if fm.modifier == "endswith":
        return f"{fm.field} LIKE {_quote(f'%{fm.value}')}"
    if fm.modifier == "re":
        return f"{fm.field} IMATCHES {_quote(fm.value)}"
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
        return f"NOT ({_render(node.child, top=True)})"
    raise TypeError(f"Unknown node type: {type(node)!r}")


class QRadarBackend(Backend):
    name = "qradar"

    def render(self, rule: "SigmaRule") -> str:
        condition = _render(rule.ast, top=True)
        return f"SELECT UTF8(payload) AS payload FROM events WHERE {condition}"
