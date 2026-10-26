from pathlib import Path

import pytest

PROBKI = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def probka():
    def wczytaj(nazwa: str) -> bytes:
        return (PROBKI / f"{nazwa}.eml").read_bytes()
    return wczytaj


@pytest.fixture
def analityk(django_user_model):
    return django_user_model.objects.create_user("anna", password="x" * 12)


@pytest.fixture
def zalogowany(client, analityk):
    client.force_login(analityk)
    return client
