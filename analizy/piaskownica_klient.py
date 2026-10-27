"""Klient sandboxa parsera. Web nigdy sam nie dekoduje plików od atakującego — wysyła je do kontenera
parser i traktuje odpowiedź jak dane niezaufane (walidacja struktury i limitów)."""

import json
import logging
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


def waliduj_wynik(wynik: object) -> dict:
    if not isinstance(wynik, dict):
        raise _blad()
    if not isinstance(wynik.get("wiadomosc"), dict) or not isinstance(wynik["wiadomosc"].get("id"), str):
        raise _blad()
    if not isinstance(wynik.get("analiza"), dict):
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
        r = httpx.post(f"{settings.PIASKOWNICA_URL}/analizuj", content=dane, headers=naglowki, timeout=CZAS_ZADANIA)
    except httpx.HTTPError as e:
        raise PiaskownicaNiedostepna(type(e).__name__) from e
    if r.status_code != 200:
        raise PiaskownicaNiedostepna(f"HTTP {r.status_code}")
    if len(r.content) > MAKS_ODPOWIEDZ:
        raise _blad()
    try:
        return json.loads(r.content)
    except ValueError as e:
        raise _blad() from e


def analizuj_w_piaskownicy(dane: bytes, nazwa: str) -> dict:
    odpowiedz = _odpowiedz_w_procesie(dane, nazwa) if not settings.PIASKOWNICA_URL else _odpowiedz_z_sieci(dane, nazwa)
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
        wartosc = httpx.get(f"{settings.PIASKOWNICA_URL}/zdrowie", timeout=3).json()
    except (httpx.HTTPError, ValueError):
        wartosc = None
    _stan_cache.update(czas=time.monotonic(), wartosc=wartosc)
    return wartosc
