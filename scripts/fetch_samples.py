"""Check out each sample repository in tests/samples at its pinned commit under .samples/."""

import json
from pathlib import Path

from _checkout import ensure_checkout

ROOT = Path(__file__).resolve().parent.parent
GOLDENS = ROOT / "tests" / "samples"
CHECKOUTS = ROOT / ".samples"


def main() -> None:
    for golden in sorted(GOLDENS.glob("*.json")):
        sample = json.loads(golden.read_text(encoding="utf-8"))
        ensure_checkout(sample["repo"], sample["sha"], CHECKOUTS)


if __name__ == "__main__":
    main()
