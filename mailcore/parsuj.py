"""Punkt wejścia: wykrycie typu pliku, rekurencja po zagnieżdżonych wiadomościach, limity."""

import re

from .eml import TYP_EML, parsuj_eml
from .model import (
    BladParsowania,
    Limity,
    NieobslugiwanyPlik,
    Ostrzezenie,
    PlikZaDuzy,
    Wiadomosc,
    Zalacznik,
)

MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
TYP_MSG = "application/vnd.ms-outlook"
_LINIA_NAGLOWKA = re.compile(rb"^[\x21-\x39\x3b-\x7e]+:")


def _typ_pliku(dane: bytes) -> str:
    if dane.startswith(MAGIC_OLE):
        return "msg"
    for linia in dane[:4096].splitlines():
        if not linia.strip():
            continue
        if linia.startswith(b"From "):  # linia separatora mbox
            continue
        if _LINIA_NAGLOWKA.match(linia):
            return "eml"
        break
    raise NieobslugiwanyPlik("Plik nie jest wiadomością .eml ani .msg.")


def _parsuj_poziom(dane: bytes, id: str) -> Wiadomosc:
    if _typ_pliku(dane) == "msg":
        from .msg import parsuj_msg

        return parsuj_msg(dane, id)
    return parsuj_eml(dane, id)


def czy_wiadomosc(z: Zalacznik) -> bool:
    nazwa = z.nazwa.lower()
    return (
        z.typ_mime in (TYP_EML, TYP_MSG)
        or nazwa.endswith(".eml")
        or nazwa.endswith(".msg")
    )


class _Parser:
    def __init__(self, limity: Limity):
        self.limity = limity

    def wiadomosc(self, dane: bytes, id: str, glebokosc: int) -> Wiadomosc:
        w = _parsuj_poziom(dane, id)
        licznik = [0]
        for z in w.zalaczniki:
            self.zalacznik(z, w, glebokosc, licznik)
        return w

    def zalacznik(self, z: Zalacznik, rodzic: Wiadomosc, glebokosc: int, licznik: list[int]) -> None:
        if not czy_wiadomosc(z):
            return
        if glebokosc + 1 > self.limity.max_glebokosc:
            if not any(o.kod == "LIMIT_GLEBOKOSC" for o in rodzic.ostrzezenia):
                rodzic.ostrzezenia.append(
                    Ostrzezenie(
                        "LIMIT_GLEBOKOSC",
                        f"Przerwano analizę zagnieżdżeń powyżej {self.limity.max_glebokosc} poziomów.",
                    )
                )
            return
        licznik[0] += 1
        try:
            z.wiadomosc = self.wiadomosc(z.dane, f"{rodzic.id}.{licznik[0]}", glebokosc + 1)
        except BladParsowania:
            rodzic.ostrzezenia.append(
                Ostrzezenie("USZKODZONA_WIADOMOSC", f"Załącznik {z.nazwa} nie jest prawidłową wiadomością.")
            )


def parsuj(dane: bytes, nazwa: str, limity: Limity = Limity()) -> Wiadomosc:
    if len(dane) > limity.max_rozmiar:
        raise PlikZaDuzy(f"Plik {nazwa} przekracza {limity.max_rozmiar} bajtów.")
    return _Parser(limity).wiadomosc(dane, "0", 0)
