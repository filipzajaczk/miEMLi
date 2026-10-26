from pathlib import Path

import pytest

NAGRANIA = Path(__file__).resolve().parent / "nagrania"
ENV = Path(__file__).resolve().parents[2] / ".env"


def _klucze() -> list[str]:
    if not ENV.exists():
        return []
    wartosci = []
    for linia in ENV.read_text().splitlines():
        k, _, v = linia.partition("=")
        if k.strip() in ("GTI_API_KEY", "CENSYS_API_TOKEN", "CENSYS_ORG_ID") and v.strip():
            wartosci.append(v.strip())
    return wartosci


def test_nagrania_bez_kluczy():
    klucze = _klucze()
    if not klucze:
        pytest.skip("brak kluczy w .env")
    for plik in NAGRANIA.glob("*.json"):
        tresc = plik.read_text(encoding="utf-8")
        assert not any(k in tresc for k in klucze), plik.name
