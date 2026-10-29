"""Analiza sparsowanej wiadomości: nagłówki, linki, IOC. Bez Django, bez sieci."""

from collections.abc import Iterator
from dataclasses import dataclass

from ..model import Wiadomosc, Zalacznik
from .ioc import IOC, zbuduj_ioc
from .linki import Link, wyciagnij_linki
from .podszywanie import Sygnal, wykryj_podszywanie
from .received import Hop, sciezka_received, sygnaly_czasu
from .uwierzytelnienie import Uwierzytelnienie, sprawdz_uwierzytelnienie


@dataclass
class AnalizaWiadomosci:
    uwierzytelnienie: Uwierzytelnienie
    received: list[Hop]
    sygnaly: list[Sygnal]
    linki: list[Link]


@dataclass
class WynikAnalizy:
    wiadomosci: dict[str, AnalizaWiadomosci]
    ioc: list[IOC]


def _zalaczniki(lista: list[Zalacznik]) -> Iterator[Zalacznik]:
    for z in lista:
        yield z
        yield from _zalaczniki(z.dzieci)


def wszystkie_wiadomosci(w: Wiadomosc) -> Iterator[Wiadomosc]:
    yield w
    for z in _zalaczniki(w.zalaczniki):
        if z.wiadomosc is not None:
            yield from wszystkie_wiadomosci(z.wiadomosc)


def analizuj(w: Wiadomosc, ignorowane_domeny: frozenset[str] = frozenset()) -> WynikAnalizy:
    wiadomosci = {}
    for x in wszystkie_wiadomosci(w):
        hopy = sciezka_received(x)
        wiadomosci[x.id] = AnalizaWiadomosci(
            sprawdz_uwierzytelnienie(x), hopy, wykryj_podszywanie(x) + sygnaly_czasu(x, hopy), wyciagnij_linki(x)
        )
    return WynikAnalizy(wiadomosci, zbuduj_ioc(w, wiadomosci, ignorowane_domeny))
