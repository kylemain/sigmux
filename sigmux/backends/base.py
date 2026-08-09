"""Shared interface for query-language backends."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rule import SigmaRule


class Backend(ABC):
    """Turns a parsed Sigma rule's AST into a target query string."""

    name: str

    @abstractmethod
    def render(self, rule: "SigmaRule") -> str:
        ...
