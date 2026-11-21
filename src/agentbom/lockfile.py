"""agentbom.lock: the reviewed definition of every artifact, and the drift from it."""

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    JsonValue,
    StringConstraints,
    ValidationError,
    model_validator,
)

from agentbom.models import Artifact, ArtifactKind, Change, Drift, FieldChange, Location

LOCKFILE_NAME = "agentbom.lock"
LOCK_VERSION: Literal[1] = 1
DIGEST_PREFIX = "sha256:"

FieldPath = tuple[str, ...]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]

# The lockfile is committed and reviewed. Secret maps keep only their keys, because even a
# digest confirms a guessed value; the file digest still catches a changed value. Bodies
# are too long to read in a pull request, so they keep a digest.
_KEYS_ONLY: dict[ArtifactKind, tuple[FieldPath, ...]] = {
    "mcp_server": (("launch", "env"), ("launch", "headers")),
    "settings": (("env",),),
}
_DIGESTED: dict[ArtifactKind, tuple[FieldPath, ...]] = {
    "skill": (("body",),),
    "rules": (("body",),),
    "script": (("body",),),
}
_MAX_ERROR_LOCATION = 6
# The id holds kind, path and name; agents and body_line are not content; a skill's
# description is a copy of its frontmatter description.
_NOT_DEFINITION = frozenset({"kind", "name", "source", "agents", "body_line", "description"})


class LockError(ValueError):
    pass


class _LockModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class LockEntry(_LockModel):
    kind: ArtifactKind
    path: str
    name: str
    definition: dict[str, JsonValue]

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.path}:{self.name}"


class Lockfile(_LockModel):
    """Each artifact's definition for a readable diff, and each source file's digest.

    The file digests make the lock complete: a change the artifact model does not
    capture, such as a YAML comment or a config key no parser reads, still drifts.
    """

    version: Literal[1]
    artifacts: dict[str, LockEntry]
    files: dict[str, Digest]

    @model_validator(mode="after")
    def _keys_are_ids(self) -> Self:
        for key, entry in self.artifacts.items():
            if key != entry.id:
                raise ValueError(f"key {key!r} does not match its entry {entry.id!r}")
        return self


def lock_entry(artifact: Artifact) -> LockEntry:
    definition = artifact.model_dump(mode="json", exclude=set(_NOT_DEFINITION))
    for field_path in _KEYS_ONLY.get(artifact.kind, ()):
        _replace_in_place(definition, field_path, lambda value: sorted(value))
    for field_path in _DIGESTED.get(artifact.kind, ()):
        _replace_in_place(definition, field_path, digest_text)
    return LockEntry(
        kind=artifact.kind, path=artifact.source.path, name=artifact.name, definition=definition
    )


def build_lock(artifacts: Sequence[Artifact], file_digests: Mapping[str, str]) -> Lockfile:
    entries: dict[str, LockEntry] = {}
    for artifact in artifacts:
        entry = lock_entry(artifact)
        if entry.id in entries:
            raise ValueError(f"two artifacts share the id {entry.id!r}")
        entries[entry.id] = entry
    return Lockfile(version=LOCK_VERSION, artifacts=entries, files=dict(file_digests))


def render_lock(lock: Lockfile) -> str:
    # ensure_ascii, so a hidden character in a definition shows as an escape in review.
    document = lock.model_dump(mode="json")
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def parse_lock(text: str) -> Lockfile:
    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as error:
        raise LockError(f"invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise LockError("the top level must be an object")
    version = document.get("version")
    if type(version) is not int or version != LOCK_VERSION:
        raise LockError(f"unsupported version {version!r}; this agentbom reads version 1")
    try:
        return Lockfile.model_validate(document)
    except ValidationError as error:
        first = error.errors()[0]
        location = [str(part) for part in first["loc"]]
        if len(location) > _MAX_ERROR_LOCATION:
            location = [*location[:_MAX_ERROR_LOCATION], "..."]
        where = ".".join(location) or "top level"
        raise LockError(f"{where}: {first['msg']}") from error


def diff_lock(
    lock: Lockfile, artifacts: Sequence[Artifact], file_digests: Mapping[str, str]
) -> tuple[Drift, ...]:
    current = {artifact.id for artifact in artifacts}
    drift = [
        _drift("removed", entry, Location(path=entry.path), before=entry, after=None)
        for key, entry in lock.artifacts.items()
        if key not in current
    ]
    for artifact in artifacts:
        before, after = lock.artifacts.get(artifact.id), lock_entry(artifact)
        if before != after:
            change: Change = "added" if before is None else "changed"
            drift.append(_drift(change, after, artifact.source, before=before, after=after))
    # Every changed file is listed too, because its artifacts may not show all of the change.
    drift.extend(
        _file_drift(path, lock.files.get(path), file_digests.get(path))
        for path in lock.files.keys() | file_digests.keys()
        if lock.files.get(path) != file_digests.get(path)
    )
    return tuple(sorted(drift, key=lambda item: item.artifact_id))


def _file_drift(path: str, before: str | None, after: str | None) -> Drift:
    change: Change = "added" if before is None else "removed" if after is None else "changed"
    text = FieldChange(field="text", change=change, before=before, after=after, hidden=True)
    return Drift(
        artifact_id=f"file:{path}",
        change=change,
        kind="file",
        name=path,
        location=Location(path=path),
        fields=(text,),
    )


def _drift(
    change: Change,
    entry: LockEntry,
    location: Location,
    *,
    before: LockEntry | None,
    after: LockEntry | None,
) -> Drift:
    return Drift(
        artifact_id=entry.id,
        change=change,
        kind=entry.kind,
        name=entry.name,
        location=location,
        fields=_field_changes(entry.kind, before, after),
    )


def _field_changes(
    kind: ArtifactKind, before: LockEntry | None, after: LockEntry | None
) -> tuple[FieldChange, ...]:
    old = {} if before is None else _leaves(before.definition)
    new = {} if after is None else _leaves(after.definition)
    whole = before is None or after is None
    changes: list[FieldChange] = []
    for path in sorted(old.keys() | new.keys()):
        field = ".".join(path)
        hidden = any(path[: len(prefix)] == prefix for prefix in _DIGESTED.get(kind, ()))
        if path in old and path in new:
            if old[path] != new[path]:
                changes.append(
                    FieldChange(
                        field=field,
                        change="changed",
                        before=old[path],
                        after=new[path],
                        hidden=hidden,
                    )
                )
        elif path in old:
            if not _says_nothing(path, old[path], new, whole=whole):
                changes.append(
                    FieldChange(field=field, change="removed", before=old[path], hidden=hidden)
                )
        elif not _says_nothing(path, new[path], old, whole=whole):
            changes.append(FieldChange(field=field, change="added", after=new[path], hidden=hidden))
    return tuple(changes)


def _says_nothing(
    path: FieldPath, value: JsonValue, other: Mapping[FieldPath, JsonValue], *, whole: bool
) -> bool:
    # An empty value says nothing about an artifact that came or went, and an empty object
    # says nothing when keys inside it already show the change.
    if whole:
        return value in ({}, [])
    return value == {} and any(key[: len(path)] == path for key in other)


def _leaves(
    document: Mapping[str, JsonValue], prefix: FieldPath = ()
) -> dict[FieldPath, JsonValue]:
    # Lists stay whole, and an empty object is a leaf, so equal leaves mean equal definitions.
    leaves: dict[FieldPath, JsonValue] = {}
    for key, value in document.items():
        path = (*prefix, key)
        if isinstance(value, dict) and value:
            leaves.update(_leaves(value, path))
        else:
            leaves[path] = value
    return leaves


def _replace_in_place(
    document: dict[str, Any], path: FieldPath, replace: Callable[[Any], JsonValue]
) -> None:
    *parents, leaf = path
    for key in parents:
        child = document.get(key)
        if not isinstance(child, dict):
            return
        document = child
    if leaf in document:
        document[leaf] = replace(document[leaf])


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not valid JSON")


def digest_text(text: str) -> str:
    return DIGEST_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()
