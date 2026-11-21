"""results.jsonl of a survey: one line per scanned repository, appended as each scan ends."""

import os
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from agentbom.models import ArtifactKind, Confidence, RuleId, Severity


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FindingRow(_Record):
    rule_id: RuleId
    severity: Severity
    confidence: Confidence
    path: str
    line: int | None
    message: str
    excerpt: str | None


class Scanned(_Record):
    status: Literal["scanned"] = "scanned"
    repo: str
    sha: str
    seconds: float
    artifacts: dict[ArtifactKind, int]
    scan_errors: int
    findings: tuple[FindingRow, ...]


class CheckoutFailed(_Record):
    status: Literal["checkout_failed"] = "checkout_failed"
    repo: str
    sha: str
    error: str


Record = Annotated[Scanned | CheckoutFailed, Field(discriminator="status")]
_RECORD: TypeAdapter[Scanned | CheckoutFailed] = TypeAdapter(Record)


def read_records(path: Path) -> dict[str, Scanned | CheckoutFailed]:
    """The latest record for each repository. A last line cut short by a crash is truncated away."""
    if not path.exists():
        return {}
    data = path.read_bytes()
    complete = data[: data.rfind(b"\n") + 1]
    if len(complete) != len(data):
        with path.open("r+b") as results:
            results.truncate(len(complete))
    records: dict[str, Scanned | CheckoutFailed] = {}
    for number, line in enumerate(complete.decode("utf-8").splitlines(), start=1):
        try:
            record = _RECORD.validate_json(line)
        except ValidationError as error:
            raise SystemExit(
                f"{path}:{number} is not a survey record; move the file away to start over"
            ) from error
        records[record.repo] = record
    return records


def append_record(path: Path, record: Scanned | CheckoutFailed) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as results:
        results.write(record.model_dump_json() + "\n")
        results.flush()
        os.fsync(results.fileno())
