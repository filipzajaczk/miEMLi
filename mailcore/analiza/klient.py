"""Program pocztowy nadawcy (X-Mailer, User-Agent, X-Originating-IP) i łańcuch ARC.

ARC: tylko to, co zadeklarowały serwery pośredniczące — parser nie ma sieci, więc podpisy
nie są weryfikowane kryptograficznie.
"""

import ipaddress
import re
from dataclasses import dataclass

from ..model import Wiadomosc
from .uwierzytelnienie import _wynik

MAKS_DLUGOSC = 300
MAKS_OGNIW = 50
_NUMER = re.compile(r"^\s*i\s*=\s*(\d{1,4})\s*;\s*([^;\s]*)")


@dataclass
class Klient:
    x_mailer: str | None
    user_agent: str | None
    x_originating_ip: str | None


@dataclass
class OgniwoArc:
    i: int
    serwer: str | None
    spf: str | None
    dkim: str | None
    dmarc: str | None


@dataclass
class LancuchArc:
    ogniwa: list[OgniwoArc]
    kompletny: bool
    cv: str | None


def _tekst(wartosc: str | None) -> str | None:
    return " ".join(wartosc.split())[:MAKS_DLUGOSC] or None if wartosc else None


def _ip(wartosc: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((wartosc or "").strip().strip("[]")))
    except ValueError:
        return None


def klient(w: Wiadomosc) -> Klient:
    return Klient(_tekst(w.naglowek("X-Mailer")), _tekst(w.naglowek("User-Agent")),
                  _ip(w.naglowek("X-Originating-IP")))


def _po_numerze(w: Wiadomosc, nazwa: str) -> dict[int, str]:
    wynik = {}
    for wartosc in w.naglowki_wszystkie(nazwa):
        znaleziony = _NUMER.match(wartosc)
        if znaleziony:
            wynik.setdefault(int(znaleziony.group(1)), wartosc)
    return wynik


def lancuch_arc(w: Wiadomosc) -> LancuchArc | None:
    wyniki = _po_numerze(w, "ARC-Authentication-Results")
    pieczecie = _po_numerze(w, "ARC-Seal")
    podpisy = _po_numerze(w, "ARC-Message-Signature")
    if not (w.naglowki_wszystkie("ARC-Authentication-Results") or w.naglowki_wszystkie("ARC-Seal")
            or w.naglowki_wszystkie("ARC-Message-Signature")):
        return None
    ogniwa = []
    for i in sorted(wyniki)[:MAKS_OGNIW]:
        naglowek = wyniki[i]
        serwer = _NUMER.match(naglowek).group(2) or None
        ogniwa.append(OgniwoArc(i, _tekst(serwer), _wynik(naglowek, "spf"), _wynik(naglowek, "dkim"),
                                _wynik(naglowek, "dmarc")))
    numery = set(wyniki) | set(pieczecie) | set(podpisy)
    kompletny = bool(numery) and numery == set(range(1, max(numery) + 1)) and all(
        i in wyniki and i in pieczecie and i in podpisy for i in numery)
    cv = _wynik(pieczecie[max(pieczecie)], "cv") if pieczecie else None
    return LancuchArc(ogniwa, kompletny, cv)
