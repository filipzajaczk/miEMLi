"""Test regresyjny na zbiorze próbek: każda próbka z plikiem .expected.json obok."""

import json
from pathlib import Path

import pytest

from mailcore.analiza import analizuj, wszystkie_wiadomosci
from mailcore.parsuj import parsuj

PROBKI = Path(__file__).resolve().parent.parent / "samples"
PLIKI = sorted(p for p in PROBKI.rglob("*") if p.suffix in (".eml", ".msg")
               and p.with_suffix(".expected.json").exists())


def _ioc(wynik):
    return {("plik", i.etykieta) if i.typ == "plik" else (i.typ, i.wartosc) for i in wynik.ioc}


@pytest.mark.parametrize("plik", PLIKI, ids=lambda p: str(p.relative_to(PROBKI)))
def test_probka(plik):
    oczekiwane = json.loads(plik.with_suffix(".expected.json").read_text(encoding="utf-8"))
    w = parsuj(plik.read_bytes(), plik.name)
    wynik = analizuj(w)
    if "ioc" in oczekiwane:
        assert _ioc(wynik) == {tuple(x) for x in oczekiwane["ioc"]}
    if "uwierzytelnienie" in oczekiwane:
        u = wynik.wiadomosci["0"].uwierzytelnienie
        assert {"spf": u.spf, "dkim": u.dkim, "dmarc": u.dmarc} == oczekiwane["uwierzytelnienie"]
    if "sygnaly" in oczekiwane:
        assert {s.kod for s in wynik.wiadomosci["0"].sygnaly} == set(oczekiwane["sygnaly"])
    if "ostrzezenia" in oczekiwane:
        kody = {o.kod for x in wszystkie_wiadomosci(w) for o in x.ostrzezenia}
        assert kody == set(oczekiwane["ostrzezenia"])
