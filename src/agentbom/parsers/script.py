from collections.abc import Iterator
from pathlib import PurePosixPath

from agentbom.models import Agent, Location, ScanError, Script
from agentbom.registry import SCRIPT_LANGUAGES


def parse_script(text: str, path: str, agents: tuple[Agent, ...]) -> Iterator[Script | ScanError]:
    yield Script(
        name=path,
        source=Location(path=path, line=1),
        agents=agents,
        language=SCRIPT_LANGUAGES[PurePosixPath(path).suffix],
        body=text,
    )
