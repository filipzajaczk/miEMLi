"""Przekształcenie zapisanego wyniku analizy (JSON) w dane dla szablonów."""

from collections.abc import Iterator
from datetime import datetime

from .models import IOC, Analiza

SEKCJE = [
    ("wiadomosc", "Wiadomość"),
    ("naglowki", "Nagłówki"),
    ("received", "Received"),
    ("zalaczniki", "Załączniki"),
    ("linki", "Linki"),
    ("ioc", "IOC"),
]


def _zalaczniki(lista: list[dict]) -> Iterator[dict]:
    for z in lista:
        yield z
        yield from _zalaczniki(z["dzieci"])


def wiadomosci(wynik: dict) -> dict[str, dict]:
    """Wszystkie wiadomości (główna i zagnieżdżone) po id, w kolejności drzewa."""
    wynik_ = {}

    def odwiedz(w: dict) -> None:
        wynik_[w["id"]] = w
        for z in _zalaczniki(w["zalaczniki"]):
            if z["wiadomosc"]:
                odwiedz(z["wiadomosc"])

    odwiedz(wynik["wiadomosc"])
    return wynik_


def liczba_zalacznikow(w: dict) -> int:
    return sum(1 for _ in _zalaczniki(w["zalaczniki"]))


def hopy(received: list[dict]) -> list[dict]:
    """Hopy z opóźnieniem względem poprzedniego (sekundy) — długie przerwy bywają podejrzane."""
    wynik, poprzedni = [], None
    for numer, hop in enumerate(received, start=1):
        czas = datetime.fromisoformat(hop["czas"]) if hop["czas"] else None
        opoznienie = int((czas - poprzedni).total_seconds()) if czas and poprzedni else None
        wynik.append({**hop, "lp": numer, "czas_dt": czas, "opoznienie": opoznienie})
        poprzedni = czas or poprzedni
    return wynik


def drzewo_ioc(analiza: Analiza) -> list[tuple[IOC, int]]:
    """IOC w kolejności drzewa pochodzenia, z głębokością do wcięcia."""
    wszystkie = list(analiza.ioc.all())
    dzieci: dict[int | None, list[IOC]] = {}
    for i in wszystkie:
        dzieci.setdefault(i.rodzic_id, []).append(i)
    wynik: list[tuple[IOC, int]] = []

    def odwiedz(rodzic_id: int | None, glebokosc: int) -> None:
        for i in dzieci.get(rodzic_id, []):
            wynik.append((i, glebokosc))
            odwiedz(i.pk, glebokosc + 1)

    odwiedz(None, 0)
    return wynik
