"""Typosquatting: domena z maila łudząco podobna do domeny odbiorcy lub firmy (np. zwlk.pl i zwik.pl)."""

import email.utils
import unicodedata
from typing import NamedTuple
from urllib.parse import urlsplit

from ..domeny import domena_adresu, domena_bazowa
from ..model import Wiadomosc
from .linki import Link
from .podszywanie import DARMOWE_DOMENY, Sygnal, _adres

MIN_DLUGOSC_NAZWY = 4  # krótsze nazwy (wp, o2, abc) są do siebie podobne przypadkiem
DLUGA_NAZWA = 8  # od tej długości dopuszczamy dwie zmiany zamiast jednej
# Limity ograniczają koszt porównań (pary wzorzec × podejrzana × znaki) dla spreparowanego maila
MAKS_DLUGOSC_NAZWY = 30
MAKS_WZORCOW = 20

_HOMOGLIFY = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ο": "o", "α": "a", "ν": "v", "ı": "l", "ł": "l",
    "i": "l", "1": "l", "0": "o",
})


class _Domena(NamedTuple):
    baza: str
    nazwa: str
    koncowka: str


def _rozloz(host: str) -> _Domena:
    baza = domena_bazowa(host)
    try:
        czytelna = baza.encode("ascii").decode("idna")
    except UnicodeError:  # już w Unicode albo uszkodzony punycode
        czytelna = baza
    nazwa, _, koncowka = czytelna.partition(".")
    return _Domena(baza, nazwa, koncowka)


def _szkielet(nazwa: str) -> str:
    """Postać, w której znaki łudząco podobne stają się identyczne."""
    bez_znakow_laczacych = "".join(
        z for z in unicodedata.normalize("NFKD", nazwa) if not unicodedata.combining(z)
    )
    return bez_znakow_laczacych.translate(_HOMOGLIFY).replace("rn", "m").replace("vv", "w")


def _odleglosc(a: str, b: str) -> int:
    """Liczba wstawień, usunięć, podmian i zamian sąsiednich znaków (Damerau-Levenshtein, wariant OSA)."""
    dwa_wstecz: list[int] = []
    poprzedni = list(range(len(b) + 1))
    for i, znak_a in enumerate(a, 1):
        biezacy = [i]
        for j, znak_b in enumerate(b, 1):
            koszt = min(poprzedni[j] + 1, biezacy[j - 1] + 1, poprzedni[j - 1] + (znak_a != znak_b))
            if i > 1 and j > 1 and znak_a == b[j - 2] and a[i - 2] == znak_b:
                koszt = min(koszt, dwa_wstecz[j - 2] + 1)
            biezacy.append(koszt)
        dwa_wstecz, poprzedni = poprzedni, biezacy
    return poprzedni[-1]


def _czytelne(znaki: str) -> str:
    return "".join(z if z.isascii() else f"{z} (U+{ord(z):04X})" for z in znaki)


def _roznica(a: str, b: str) -> str:
    poczatek = 0
    while poczatek < min(len(a), len(b)) and a[poczatek] == b[poczatek]:
        poczatek += 1
    a, b = a[poczatek:], b[poczatek:]
    koniec = 0
    while koniec < min(len(a), len(b)) and a[-1 - koniec] == b[-1 - koniec]:
        koniec += 1
    a, b = a[:len(a) - koniec], b[:len(b) - koniec]
    if a and b:
        return f"„{_czytelne(a)}” zamiast „{_czytelne(b)}”"
    return f"dodatkowe „{_czytelne(a)}”" if a else f"brak „{_czytelne(b)}”"


def _powod_podobienstwa(podejrzana: _Domena, wzorzec: _Domena) -> str | None:
    if podejrzana.baza == wzorzec.baza or {podejrzana.baza, wzorzec.baza} <= DARMOWE_DOMENY:
        return None
    if len(wzorzec.nazwa) < MIN_DLUGOSC_NAZWY or not podejrzana.koncowka:
        return None
    if max(len(podejrzana.nazwa), len(wzorzec.nazwa)) > MAKS_DLUGOSC_NAZWY:
        return None
    if podejrzana.nazwa == wzorzec.nazwa:
        return f"końcówka .{podejrzana.koncowka} zamiast .{wzorzec.koncowka}"
    limit = 2 if len(wzorzec.nazwa) >= DLUGA_NAZWA else 1
    if (_szkielet(podejrzana.nazwa) == _szkielet(wzorzec.nazwa)
            or _odleglosc(podejrzana.nazwa, wzorzec.nazwa) <= limit):
        return _roznica(podejrzana.nazwa, wzorzec.nazwa)
    return None


def _domeny_odbiorcow(w: Wiadomosc) -> list[str]:
    # Outlook (.msg) rozdziela adresy średnikiem
    wartosci = [v.replace(";", ",") for n in ("To", "Cc") for v in w.naglowki_wszystkie(n)]
    return [d for _, adres in email.utils.getaddresses(wartosci) if (d := domena_adresu(adres))]


def _wzorce(w: Wiadomosc, firma: frozenset[str]) -> list[tuple[_Domena, str]]:
    # Domeny firmy na początku, żeby limit odciął najwyżej odbiorców
    wzorce: dict[str, tuple[_Domena, str]] = {}
    for hosty, rola in ((sorted(firma), "domena firmy"), (_domeny_odbiorcow(w), "odbiorca")):
        for host in hosty:
            domena = _rozloz(host)
            wzorce.setdefault(domena.baza, (domena, rola))
    return list(wzorce.values())[:MAKS_WZORCOW]


def _host_linku(link: Link) -> str | None:
    try:
        return urlsplit(link.docelowy).hostname
    except ValueError:
        return None


def _podejrzane(w: Wiadomosc, linki: list[Link]) -> dict[str, list[str]]:
    """Domena bazowa → miejsca, w których wystąpiła."""
    hosty = [
        (domena_adresu(_adres(wartosc)[1]), zrodlo)
        for wartosc, zrodlo in (
            (w.naglowek("From"), "From"),
            (w.naglowek("Reply-To"), "Reply-To"),
            (w.naglowek("Return-Path"), "Return-Path"),
        )
    ] + [(_host_linku(link), "link") for link in linki]
    wynik: dict[str, list[str]] = {}
    for host, zrodlo in hosty:
        if host:
            zrodla = wynik.setdefault(domena_bazowa(host), [])
            if zrodlo not in zrodla:
                zrodla.append(zrodlo)
    return wynik


def wykryj_podobne_domeny(w: Wiadomosc, linki: list[Link], domeny_firmy: frozenset[str]) -> list[Sygnal]:
    wzorce = _wzorce(w, domeny_firmy)
    bazy_firmy = {domena_bazowa(d) for d in domeny_firmy}
    sygnaly: list[Sygnal] = []
    for baza, zrodla in _podejrzane(w, linki).items():
        if baza in bazy_firmy:
            continue
        podejrzana = _rozloz(baza)
        for wzorzec, rola in wzorce:
            if powod := _powod_podobienstwa(podejrzana, wzorzec):
                sygnaly.append(Sygnal("DOMENA_PODOBNA", (
                    f"Domena {baza} ({', '.join(zrodla)}) łudząco podobna do {wzorzec.baza} ({rola}): {powod}."
                )))
                break
    return sygnaly
