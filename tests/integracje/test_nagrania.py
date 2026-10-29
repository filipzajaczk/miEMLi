from pathlib import Path

import pytest

NAGRANIA = Path(__file__).resolve().parent / "nagrania"
ENV = Path(__file__).resolve().parents[2] / ".env"


def _klucze(env=ENV) -> list[str]:
    if not env.exists():
        return []
    wartosci = []
    for linia in env.read_text().splitlines():
        k, _, v = linia.partition("=")
        v = v.strip().strip("\"'")
        if k.strip() in ("GTI_API_KEY", "CENSYS_API_TOKEN", "CENSYS_ORG_ID") and v:
            wartosci.append(v)
    return wartosci


def test_nagrania_bez_kluczy():
    klucze = _klucze()
    if not klucze:
        pytest.skip("brak kluczy w .env")
    for plik in NAGRANIA.glob("*.json"):
        tresc = plik.read_text(encoding="utf-8")
        assert not any(k in tresc for k in klucze), plik.name


def test_nagrania_cudzyslowy(tmp_path):
    env = tmp_path / ".env"
    env.write_text('GTI_API_KEY="abc123"\nCENSYS_API_TOKEN=\'def456\'\nCENSYS_ORG_ID=ghi\nINNE=x\n')
    assert _klucze(env) == ["abc123", "def456", "ghi"]
