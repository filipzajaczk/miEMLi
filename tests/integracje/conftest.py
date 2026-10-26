import json
from pathlib import Path

import pytest

NAGRANIA = Path(__file__).resolve().parent / "nagrania"


@pytest.fixture
def nagranie():
    def wczytaj(nazwa: str) -> tuple[int, dict]:
        d = json.loads((NAGRANIA / f"{nazwa}.json").read_text(encoding="utf-8"))
        return d["status"], d["cialo"]
    return wczytaj
