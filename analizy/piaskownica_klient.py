"""Klient sandboxa parsera. Web nigdy sam nie dekoduje plików od atakującego — wysyła je do kontenera
parser i traktuje odpowiedź jak dane niezaufane (walidacja struktury i limitów)."""

import json
import logging
import re
import time
from urllib.parse import quote

import httpx
from django.conf import settings

from mailcore.model import NieobslugiwanyPlik, PlikZaDuzy

logger = logging.getLogger(__name__)

MAKS_ODPOWIEDZ = 20 * 1024 * 1024
MAKS_IOC = 5000
MAKS_WARTOSC = 8192
TYPY_IOC = {"plik", "url", "domena", "ip", "email"}
CZAS_ZADANIA = 90.0
_stan_cache: dict = {"czas": 0.0, "wartosc": None}


class PiaskownicaNiedostepna(Exception):
    pass


class AnalizaPrzerwana(Exception):
    def __init__(self, powod: str):
        super().__init__(powod)
        self.powod = powod  # czas | pamiec | awaria | nieprawidlowa_odpowiedz


def _blad() -> AnalizaPrzerwana:
    return AnalizaPrzerwana("nieprawidlowa_odpowiedz")


MAKS_GLEBOKOSC_DRZEWA = 10
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _lista(x, typ=None) -> bool:
    return isinstance(x, list) and (typ is None or all(isinstance(e, typ) for e in x))


def _tekst_lub_none(x) -> bool:
    return x is None or isinstance(x, str)


def _zalacznik_ok(z, glebokosc: int) -> bool:
    if glebokosc > MAKS_GLEBOKOSC_DRZEWA:
        return False
    if not isinstance(z, dict) or not isinstance(z.get("nazwa"), str):
        return False
    if not isinstance(z.get("sha256"), str) or not _SHA256.fullmatch(z["sha256"]):
        return False
    if not isinstance(z.get("rozmiar"), int) or isinstance(z["rozmiar"], bool):
        return False
    if not _lista(z.get("dzieci")) or not all(_zalacznik_ok(d, glebokosc + 1) for d in z["dzieci"]):
        return False
    return z.get("wiadomosc") is None or _wiadomosc_ok(z["wiadomosc"], glebokosc + 1)


def _wiadomosc_ok(w, glebokosc: int = 0) -> bool:
    """Drzewo wiadomości od (potencjalnie przejętego) parsera — szablony zakładają te typy."""
    if glebokosc > MAKS_GLEBOKOSC_DRZEWA or not isinstance(w, dict) or not isinstance(w.get("id"), str):
        return False
    if not all(_tekst_lub_none(w.get(p)) for p in ("temat", "od", "data", "tekst", "html_bezpieczny")):
        return False
    naglowki = w.get("naglowki")
    if not _lista(naglowki) or not all(_lista(n, str) and len(n) == 2 for n in naglowki):
        return False
    if not _lista(w.get("do", []), str) or not _lista(w.get("obrazki", []), dict):
        return False
    for o in w.get("obrazki", []):
        uwagi = o.get("uwagi", [])
        if not _lista(uwagi, dict) or not all(isinstance(u.get("kod"), str) for u in uwagi):
            return False
    ostrzezenia = w.get("ostrzezenia", [])
    if not _lista(ostrzezenia, dict) or not all(_tekst_lub_none(o.get("kod")) for o in ostrzezenia):
        return False
    return _lista(w.get("zalaczniki")) and all(_zalacznik_ok(z, glebokosc) for z in w["zalaczniki"])


def _krotki_tekst(x, limit: int = 300) -> bool:
    return x is None or (isinstance(x, str) and len(x) <= limit)


def _klient_ok(k) -> bool:
    return k is None or (isinstance(k, dict) and all(
        _krotki_tekst(k.get(p)) for p in ("x_mailer", "user_agent", "x_originating_ip")))


def _arc_ok(arc) -> bool:
    if arc is None:
        return True
    if not isinstance(arc, dict) or not isinstance(arc.get("kompletny"), bool) or not _krotki_tekst(arc.get("cv")):
        return False
    ogniwa = arc.get("ogniwa")
    return _lista(ogniwa, dict) and len(ogniwa) <= 50 and all(
        isinstance(o.get("i"), int) and not isinstance(o["i"], bool)
        and all(_krotki_tekst(o.get(p)) for p in ("serwer", "spf", "dkim", "dmarc"))
        for o in ogniwa)


def _uwagi_ok(uwagi) -> bool:
    return _lista(uwagi, dict) and all(isinstance(u.get("kod"), str) and isinstance(u.get("opis"), str)
                                       for u in uwagi)


def _analiza_ok(a) -> bool:
    return isinstance(a, dict) and all(
        isinstance(k, str) and isinstance(v, dict)
        and all(_lista(v.get(p, []), dict) for p in ("received", "sygnaly", "linki"))
        and all(_uwagi_ok(h.get("uwagi", [])) for h in v.get("received", []))
        and _klient_ok(v.get("klient")) and _arc_ok(v.get("arc"))
        for k, v in a.items()
    )


def waliduj_wynik(wynik: object) -> dict:
    if not isinstance(wynik, dict):
        raise _blad()
    try:
        poprawna = _wiadomosc_ok(wynik.get("wiadomosc"))
    except RecursionError:
        poprawna = False
    if not poprawna:
        raise _blad()
    if not _analiza_ok(wynik.get("analiza")):
        raise _blad()
    lista = wynik.get("ioc")
    if not isinstance(lista, list) or len(lista) > MAKS_IOC:
        raise _blad()
    for i in lista:
        if not isinstance(i, dict) or i.get("typ") not in TYPY_IOC:
            raise _blad()
        if not isinstance(i.get("wartosc"), str) or len(i["wartosc"]) > MAKS_WARTOSC:
            raise _blad()
        if not isinstance(i.get("id"), int) or isinstance(i["id"], bool):
            raise _blad()
        rodzic = i.get("rodzic_id")
        if rodzic is not None and (not isinstance(rodzic, int) or rodzic >= i["id"]):
            raise _blad()
        for pole in ("etykieta", "haslo_archiwum", "zrodlo"):
            if i.get(pole) is not None and not isinstance(i[pole], str):
                raise _blad()
        if i.get("hashe") is not None and not isinstance(i["hashe"], dict):
            raise _blad()
    return wynik


def _odpowiedz_w_procesie(dane: bytes, nazwa: str) -> dict:
    """Tryb deweloperski/testowy (PIASKOWNICA_URL pusty): ten sam kod co proces potomny, bez izolacji."""
    from piaskownica.zadanie import analizuj_plik

    return analizuj_plik(dane, nazwa, settings.MIEMLI_IGNOROWANE_DOMENY, settings.MAKS_ROZMIAR_PLIKU)


def _odpowiedz_z_sieci(dane: bytes, nazwa: str) -> dict:
    naglowki = {
        "X-Miemli-Nazwa": quote(nazwa[:255], safe="")[:255],
        "X-Miemli-Ignorowane": ",".join(sorted(settings.MIEMLI_IGNOROWANE_DOMENY)),
        "X-Miemli-Max-Rozmiar": str(settings.MAKS_ROZMIAR_PLIKU),
        "Content-Type": "application/octet-stream",
    }
    try:
        with httpx.stream("POST", f"{settings.PIASKOWNICA_URL}/analizuj", content=dane, headers=naglowki,
                          timeout=CZAS_ZADANIA) as r:
            if r.status_code != 200:
                raise PiaskownicaNiedostepna(f"HTTP {r.status_code}")
            tresc = _czytaj_z_limitem(r, MAKS_ODPOWIEDZ)
    except httpx.HTTPError as e:
        raise PiaskownicaNiedostepna(type(e).__name__) from e
    if tresc is None:
        raise _blad()
    try:
        return json.loads(tresc)
    except (ValueError, RecursionError) as e:
        raise _blad() from e


def _czytaj_z_limitem(odpowiedz: httpx.Response, limit: int) -> bytes | None:
    """Czyta strumieniowo; None, gdy treść przekracza limit (nie trzymamy w pamięci więcej niż limit)."""
    bufor = bytearray()
    for kawalek in odpowiedz.iter_bytes():
        bufor.extend(kawalek)
        if len(bufor) > limit:
            return None
    return bytes(bufor)


def analizuj_w_piaskownicy(dane: bytes, nazwa: str) -> dict:
    if not settings.PIASKOWNICA_URL:
        if not (settings.DEBUG or settings.PIASKOWNICA_W_PROCESIE):
            # pusty URL na produkcji nie może po cichu wyłączyć sandboxa
            logger.error("PIASKOWNICA_URL pusty bez DEBUG/PIASKOWNICA_W_PROCESIE — odmowa analizy")
            raise PiaskownicaNiedostepna("brak konfiguracji sandboxa")
        odpowiedz = _odpowiedz_w_procesie(dane, nazwa)
    else:
        odpowiedz = _odpowiedz_z_sieci(dane, nazwa)
    if not isinstance(odpowiedz, dict):
        raise _blad()
    if odpowiedz.get("status") == "przerwana":
        powod = odpowiedz.get("powod")
        if powod == "nieobslugiwany":
            raise NieobslugiwanyPlik("Plik nie jest wiadomością .eml ani .msg.")
        if powod == "za_duzy":
            raise PlikZaDuzy("Plik przekracza limit.")
        if powod in ("czas", "pamiec", "awaria"):
            raise AnalizaPrzerwana(powod)
        raise _blad()
    if odpowiedz.get("status") != "ok":
        raise _blad()
    return waliduj_wynik(odpowiedz.get("wynik"))


def stan_piaskownicy() -> dict | None:
    """GET /zdrowie z 60-sekundowym cache; None w trybie w procesie lub gdy parser nie odpowiada."""
    if not settings.PIASKOWNICA_URL:
        return None
    if time.monotonic() - _stan_cache["czas"] < 60:
        return _stan_cache["wartosc"]
    try:
        with httpx.stream("GET", f"{settings.PIASKOWNICA_URL}/zdrowie", timeout=3) as r:
            tresc = _czytaj_z_limitem(r, 64 * 1024)
        wartosc = json.loads(tresc) if tresc is not None else None
    except (httpx.HTTPError, ValueError, RecursionError):
        wartosc = None
    if not isinstance(wartosc, dict):
        wartosc = None
    _stan_cache.update(czas=time.monotonic(), wartosc=wartosc)
    return wartosc
