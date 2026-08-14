"""Google Security Operations (Chronicle) YARA-L 2.0 backend.

Unlike the other backends, this doesn't render a bare query expression --
YARA-L rules are a small structured language of their own (`meta` /
`events` / `condition` blocks), so this backend builds the whole rule
skeleton around the same field-match/boolean AST every other backend walks.

Two things are deliberately best-effort, in the same spirit as the Sentinel
backend's logsource->table map:
- `metadata.event_type` is guessed from the Sigma logsource the same way
  Sentinel guesses its table, defaulting to `GENERIC_EVENT`.
- Field names are emitted as the raw Sigma field name under the event
  variable (`$e.Image`, ...) rather than mapped onto Chronicle's real UDM
  schema (`$e.target.process.file.full_path`, ...) -- that mapping is
  product/log-source-specific and out of scope here.
"""
from __future__ import annotations

import re as _re
from typing import TYPE_CHECKING, Dict, Optional, Tuple

from ..ast_nodes import And, FieldMatch, Node, Not, Or
from .base import Backend

if TYPE_CHECKING:
    from ..rule import SigmaRule

_EVENT_TYPE_MAP: Dict[Tuple[Optional[str], Optional[str]], str] = {
    ("process_creation", None): "PROCESS_LAUNCH",
    ("network_connection", None): "NETWORK_CONNECTION",
    ("file_event", None): "FILE_CREATION",
    ("file_change", None): "FILE_MODIFICATION",
    ("registry_event", None): "REGISTRY_MODIFICATION",
    ("registry_add", None): "REGISTRY_CREATION",
}
_DEFAULT_EVENT_TYPE = "GENERIC_EVENT"


def _event_type_for(logsource: Dict[str, str]) -> str:
    category = logsource.get("category")
    return _EVENT_TYPE_MAP.get((category, None), _DEFAULT_EVENT_TYPE)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rule_name(title: str) -> str:
    name = _re.sub(r"[^A-Za-z0-9_]", "_", title).strip("_")
    if not name:
        name = "sigma_rule"
    if name[0].isdigit():
        name = f"rule_{name}"
    return name


def _match(fm: FieldMatch) -> str:
    if fm.modifier == "eq":
        return f"$e.{fm.field} = {_quote(fm.value)}"
    if fm.modifier == "contains":
        return f"$e.{fm.field} contains {_quote(fm.value)}"
    if fm.modifier == "startswith":
        return f're.regex($e.{fm.field}, {_quote("^" + _re.escape(fm.value))})'
    if fm.modifier == "endswith":
        return f're.regex($e.{fm.field}, {_quote(_re.escape(fm.value) + "$")})'
    if fm.modifier == "re":
        return f"re.regex($e.{fm.field}, {_quote(fm.value)})"
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


class ChronicleBackend(Backend):
    name = "chronicle"

    def render(self, rule: "SigmaRule") -> str:
        event_type = _event_type_for(rule.logsource)
        expr = _render(rule.ast, top=True)

        meta_lines = ['author = "sigmux"']
        if rule.description:
            meta_lines.append(f"description = {_quote(rule.description)}")
        if rule.level:
            meta_lines.append(f'severity = "{rule.level.upper()}"')
        if rule.id:
            meta_lines.append(f'reference = "{rule.id}"')
        meta_block = "\n".join(f"    {line}" for line in meta_lines)

        return (
            f"rule {_rule_name(rule.title)} {{\n"
            f"  meta:\n{meta_block}\n\n"
            f"  events:\n"
            f'    $e.metadata.event_type = "{event_type}"\n'
            f"    {expr}\n\n"
            f"  condition:\n"
            f"    $e\n"
            f"}}"
        )
