"""Backend registry: maps a target name to its converter implementation.

Target names match detectl's platform names 1:1 (elastic, crowdstrike,
sentinel, splunk, qradar, sumologic, chronicle) -- deliberately, so a
sigmux target and the detectl platform you'd push its output to are always
the same name. See "Pairs well with detectl" in the README.
"""
from .base import Backend
from .chronicle import ChronicleBackend
from .crowdstrike import CrowdStrikeBackend
from .elastic import ElasticBackend
from .qradar import QRadarBackend
from .sentinel import SentinelBackend
from .splunk import SplunkBackend
from .sumologic import SumoLogicBackend

REGISTRY = {
    "splunk": SplunkBackend(),
    "elastic": ElasticBackend(),
    "sentinel": SentinelBackend(),
    "crowdstrike": CrowdStrikeBackend(),
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
