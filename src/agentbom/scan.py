from pathlib import Path

from agentbom.discover import discover
from agentbom.models import Artifact, ScanError, ScanResult
from agentbom.parsers import parse


def scan(root: Path) -> ScanResult:
    sources, errors = discover(root)
    artifacts: list[Artifact] = []
    for source in sources:
        found, failed = parse(
            source.text, source.path, source.pattern.format, source.pattern.agents
        )
        artifacts.extend(found)
        errors.extend(failed)
    return ScanResult(
        artifacts=tuple(sorted(artifacts, key=lambda a: (a.kind, a.source.path, a.name))),
        errors=tuple(sorted(errors, key=_error_key)),
    )


def _error_key(error: ScanError) -> tuple[str, str]:
    return error.path, error.message
