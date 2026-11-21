from pathlib import Path

from agentbom.discover import discover
from agentbom.lockfile import Lockfile, diff_lock, digest_link, digest_text
from agentbom.models import Artifact, ScanError, ScanResult
from agentbom.parsers import parse
from agentbom.rules import run_rules


def scan(root: Path, lock: Lockfile | None = None) -> ScanResult:
    """Inventory and analyze `root`; with a lock, also report drift from it as ABOM-006."""
    found_files = discover(root)
    sources, errors = found_files.sources, found_files.errors
    artifacts: list[Artifact] = []
    for source in sources:
        found, failed = parse(
            source.text, source.path, source.pattern.format, source.pattern.agents
        )
        artifacts.extend(found)
        errors.extend(failed)
    ordered = tuple(sorted(artifacts, key=lambda a: (a.kind, a.source.path, a.name)))
    file_digests = {source.path: digest_text(source.text) for source in sources}
    file_digests.update({path: digest_link(target) for path, target in found_files.links.items()})
    drift = () if lock is None else diff_lock(lock, ordered, file_digests)
    return ScanResult(
        artifacts=ordered,
        errors=tuple(sorted(errors, key=_error_key)),
        findings=run_rules(ordered, drift),
        drift=drift,
        file_digests=file_digests,
    )


def _error_key(error: ScanError) -> tuple[str, str]:
    return error.path, error.message
