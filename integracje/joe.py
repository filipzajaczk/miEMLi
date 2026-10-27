"""Klient Joe Sandbox Cloud (API v2). Klucz zawsze w treści formularza (`apikey`), nigdy w nagłówku.
Odpowiedzi traktowane jako niezaufane: limit rozmiaru, walidacja typów i identyfikatorów."""

import json
import re
from dataclasses import dataclass, field

import httpx

from .wspolne import TIMEOUT, USER_AGENT

BAZA = "https://jbxcloud.joesecurity.org/api"
GUI = "https://jbxcloud.joesecurity.org/analysis/{webid}"
PARAMETRY = {
    "live-interaction": "1",
    "internet-access": "1",
    "url-reputation": "0",  # adresy z maila nie trafiają do zewnętrznych serwisów reputacyjnych
    "delete-after-days": "30",
    "accept-tac": "1",
}
MAKS_ODPOWIEDZ = 1024 * 1024
CZAS_WYSYLKI = 60.0
_IDENTYFIKATOR = re.compile(r"[A-Za-z0-9_-]{1,64}")
_STATUSY = {"submitted": "w_kolejce", "running": "trwa", "finished": "zakonczone"}
_WERDYKTY = {"malicious": "zlosliwy", "suspicious": "podejrzany", "clean": "czysty"}
NIEPRAWIDLOWA = "Nieprawidłowa odpowiedź Joe."


@dataclass
class WynikJoe:
    status: str  # "ok" | "odrzucony" | "limit" | "niedostepny"
    dane: dict = field(default_factory=dict)
    blad: str = ""
    ponawiac: bool = False


class _Nieprawidlowa(Exception):
    pass


def link_analizy(webid: str) -> str:
    if not isinstance(webid, str) or not _IDENTYFIKATOR.fullmatch(webid):
        raise ValueError("nieprawidłowy webid")
    return GUI.format(webid=webid)


def _identyfikator(wartosc) -> str:
    wartosc = str(wartosc) if isinstance(wartosc, (str, int)) and not isinstance(wartosc, bool) else ""
    if not _IDENTYFIKATOR.fullmatch(wartosc):
        raise _Nieprawidlowa
    return wartosc


def _zapytanie(sciezka: str, pola: dict, baza: str, pliki: dict | None = None,
               czas: float = TIMEOUT) -> tuple[int, object]:
    """(kod HTTP, zdekodowany JSON albo None). Odczyt strumieniowy z limitem rozmiaru."""
    with httpx.stream("POST", f"{baza}{sciezka}", data=pola, files=pliki, timeout=czas,
                      headers={"User-Agent": USER_AGENT}) as r:
        bufor = bytearray()
        for kawalek in r.iter_bytes():
            bufor.extend(kawalek)
            if len(bufor) > MAKS_ODPOWIEDZ:
                raise _Nieprawidlowa
        try:
            return r.status_code, json.loads(bufor) if bufor else None
        except (ValueError, RecursionError):
            return r.status_code, None


def _wykonaj(sciezka: str, klucz: str, pola: dict, baza: str, przetworz, pliki=None, czas=TIMEOUT) -> WynikJoe:
    try:
        kod, odp = _zapytanie(sciezka, {"apikey": klucz, **pola}, baza, pliki, czas)
    except _Nieprawidlowa:
        return WynikJoe("niedostepny", blad=NIEPRAWIDLOWA)
    except httpx.HTTPError:
        return WynikJoe("niedostepny", blad="Joe niedostępny.", ponawiac=True)
    if kod in (401, 403):
        return WynikJoe("odrzucony", blad="Klucz Joe odrzucony — sprawdź go w profilu.")
    if kod == 429:
        return WynikJoe("limit", blad="Wyczerpany limit Joe.", ponawiac=True)
    if kod >= 500:
        return WynikJoe("niedostepny", blad="Joe niedostępny.", ponawiac=True)
    if isinstance(odp, dict) and isinstance(odp.get("errors"), list) and odp["errors"]:
        pierwszy = odp["errors"][0]
        komunikat = str(pierwszy.get("message", "") if isinstance(pierwszy, dict) else pierwszy)[:200]
        return WynikJoe("odrzucony", blad=f"Joe nie przyjął pliku: {komunikat}")
    if kod != 200 or not isinstance(odp, dict) or not isinstance(odp.get("data"), dict):
        return WynikJoe("niedostepny", blad=NIEPRAWIDLOWA)
    try:
        return WynikJoe("ok", przetworz(odp["data"]))
    except (_Nieprawidlowa, ValueError, TypeError, KeyError):
        return WynikJoe("niedostepny", blad=NIEPRAWIDLOWA)


def wyslij(klucz: str, dane: bytes, nazwa_pliku: str, komentarz: str, baza: str = BAZA) -> WynikJoe:
    return _wykonaj(
        "/v2/submission/new", klucz, {**PARAMETRY, "comments": komentarz}, baza,
        lambda d: {"id_zgloszenia": _identyfikator(d.get("submission_id"))},
        pliki={"sample": (nazwa_pliku, dane, "application/octet-stream")}, czas=CZAS_WYSYLKI,
    )


def _stan(d: dict) -> dict:
    analizy = d.get("analyses") if isinstance(d.get("analyses"), list) else []
    pierwsza = analizy[0] if analizy and isinstance(analizy[0], dict) else {}
    webid = _identyfikator(pierwsza["webid"]) if pierwsza.get("webid") is not None else None
    status = _STATUSY.get(d.get("status"), "w_kolejce")
    werdykt = wynik = None
    if status == "zakonczone":
        istotna = d.get("most_relevant_analysis") if isinstance(d.get("most_relevant_analysis"), dict) else pierwsza
        werdykt = _WERDYKTY.get(istotna.get("detection"), "nieznany")
        wynik = istotna.get("score") if isinstance(istotna.get("score"), int) and not isinstance(istotna.get("score"), bool) else None
    return {"status": status, "webid": webid, "werdykt": werdykt, "wynik": wynik}


def stan_zgloszenia(klucz: str, id_zgloszenia: str, baza: str = BAZA) -> WynikJoe:
    return _wykonaj("/v2/submission/info", klucz, {"submission_id": id_zgloszenia}, baza, _stan)


def info_konta(klucz: str, baza: str = BAZA) -> WynikJoe:
    return _wykonaj("/v2/account/info", klucz, {}, baza, lambda d: {})
