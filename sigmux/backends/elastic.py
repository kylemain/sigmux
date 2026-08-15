"""Elasticsearch Query DSL backend (emits real bool-query JSON)."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule


def _leaf(fm: FieldMatch) -> Dict[str, Any]:
    if fm.modifier == "eq":
        return {"match_phrase": {fm.field: fm.value}}
    if fm.modifier == "contains":
        return {"wildcard": {fm.field: f"*{fm.value}*"}}
    if fm.modifier == "startswith":
        return {"wildcard": {fm.field: f"{fm.value}*"}}
    if fm.modifier == "endswith":
        return {"wildcard": {fm.field: f"*{fm.value}"}}
    if fm.modifier == "re":
        return {"regexp": {fm.field: fm.value}}
    raise ValueError(f"Unsupported modifier: {fm.modifier}")


def _render(node: Node) -> Dict[str, Any]:
    if isinstance(node, FieldMatch):
        return _leaf(node)
    if isinstance(node, And):
        return {"bool": {"must": [_render(c) for c in node.children]}}
    if isinstance(node, Or):
        return {
            "bool": {
                "should": [_render(c) for c in node.children],
                "minimum_should_match": 1,
            }
        }
    if isinstance(node, Not):
        return {"bool": {"must_not": [_render(node.child)]}}
    raise TypeError(f"Unknown node type: {type(node)!r}")


class ElasticBackend(Backend):
    name = "elastic"

    def render(self, rule: "SigmaRule") -> str:
        return json.dumps({"query": _render(rule.ast)}, indent=2)
