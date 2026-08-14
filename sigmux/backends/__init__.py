"""Backend registry: maps a target name to its converter implementation."""
from .base import Backend
from .chronicle import ChronicleBackend
from .elasticsearch import ElasticsearchBackend
from .logscale import LogScaleBackend
from .qradar import QRadarBackend
from .sentinel import SentinelBackend
from .splunk import SplunkBackend
from .sumologic import SumoLogicBackend

REGISTRY = {
    "splunk": SplunkBackend(),
    "elasticsearch": ElasticsearchBackend(),
    "sentinel": SentinelBackend(),
    "logscale": LogScaleBackend(),
    "qradar": QRadarBackend(),
    "chronicle": ChronicleBackend(),
    "sumologic": SumoLogicBackend(),
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
