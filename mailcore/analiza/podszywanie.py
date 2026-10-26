import email.utils
import re
from dataclasses import dataclass

from ..domeny import domena_adresu, domena_bazowa
from ..model import Wiadomosc

DARMOWE_DOMENY = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "icloud.com", "proton.me", "protonmail.com", "wp.pl", "o2.pl", "onet.pl", "op.pl",
    "interia.pl", "gazeta.pl", "poczta.fm", "tlen.pl",
})
_ADRES_W_NAZWIE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)|\b((?:[\w-]+\.)+[a-z]{2,})\b", re.IGNORECASE)


@dataclass
class Sygnal:
    kod: str
    opis: str


def _adres(wartosc: str | None) -> tuple[str, str]:
    nazwa, adres = email.utils.parseaddr(wartosc or "")
    return nazwa, adres


def _rozne(d1: str | None, d2: str | None) -> bool:
    return bool(d1 and d2) and domena_bazowa(d1) != domena_bazowa(d2)


def wykryj_podszywanie(w: Wiadomosc) -> list[Sygnal]:
    nazwa, adres_od = _adres(w.od)
    domena_od = domena_adresu(adres_od)
    if not domena_od:
        return []
    sygnaly: list[Sygnal] = []

    _, reply_to = _adres(w.naglowek("Reply-To"))
    domena_reply = domena_adresu(reply_to)
    if _rozne(domena_od, domena_reply):
        sygnaly.append(Sygnal("REPLY_TO_INNA_DOMENA", f"Odpowiedź trafi do {reply_to}, a nie do domeny nadawcy."))

    _, return_path = _adres(w.naglowek("Return-Path"))
    if _rozne(domena_od, domena_adresu(return_path)):
        sygnaly.append(Sygnal("RETURN_PATH_INNA_DOMENA", f"Return-Path ({return_path}) z innej domeny niż From."))

    for znaleziony in _ADRES_W_NAZWIE.finditer(nazwa):
        domena = znaleziony.group(1) or znaleziony.group(2)
        if _rozne(domena_od, domena):
            sygnaly.append(Sygnal("NAZWA_Z_INNYM_ADRESEM", f"Nazwa nadawcy zawiera {domena}, a adres to {adres_od}."))
            break

    darmowe = [d for d in (domena_od, domena_reply) if d in DARMOWE_DOMENY]
    if darmowe:
        sygnaly.append(Sygnal("DARMOWA_POCZTA", f"Adres w darmowej poczcie: {darmowe[0]}."))
    return sygnaly
