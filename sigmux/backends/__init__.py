"""Backend registry: maps a target name to its converter implementation."""
from .base import Backend
from .elasticsearch import ElasticsearchBackend
from .sentinel import SentinelBackend
from .splunk import SplunkBackend

REGISTRY = {
    "splunk": SplunkBackend(),
    "elasticsearch": ElasticsearchBackend(),
    "sentinel": SentinelBackend(),
}


def get_backend(name: str) -> Backend:
    try:
        return REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(sorted(REGISTRY))
        raise ValueError(
            f"Unknown target '{name}'. Available targets: {available}"
        ) from exc


__all__ = ["Backend", "REGISTRY", "get_backend"]
