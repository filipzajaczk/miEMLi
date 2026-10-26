"""Google Threat Intelligence (API v3 w stylu VirusTotal) — lookupy bez wysyłania plików."""

import base64
import hashlib

import httpx

from .wspolne import WynikDostawcy, nowy_klient, wykonaj

BAZA = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
WERDYKTY = {
    "VERDICT_MALICIOUS": "zlosliwy",
    "VERDICT_SUSPICIOUS": "podejrzany",
    "VERDICT_BENIGN": "nieszkodliwy",
}


def id_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _wartosc(slownik: dict, klucz: str):
    pole = slownik.get(klucz)
    return pole.get("value") if isinstance(pole, dict) else None


def skrot_gti(odpowiedz: dict) -> dict:
    a = odpowiedz["data"]["attributes"]
    ocena = a.get("gti_assessment") or {}
    stat = a.get("last_analysis_stats")
    wykrycia = None
    if isinstance(stat, dict):
        wszystkie = sum(stat.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
        wykrycia = [stat.get("malicious", 0), wszystkie]
    return {
        "werdykt": WERDYKTY.get(_wartosc(ocena, "verdict"), "niewykryty"),
        "ocena": _wartosc(ocena, "threat_score"),
        "waznosc": _wartosc(ocena, "severity"),
        "wykrycia": wykrycia,
        "utworzono": a.get("creation_date"),
        "rejestrator": a.get("registrar"),
        "kraj": a.get("country"),
        "asn": a.get("asn"),
        "wlasciciel": a.get("as_owner"),
        "typ_pliku": a.get("type_description"),
        "nazwy": list(a.get("names") or [])[:5],
        "tagi": list(a.get("tags") or [])[:10],
        "pierwsze": a.get("first_seen_itw_date"),
        "ostatnia_analiza": a.get("last_analysis_date"),
    }


class KlientGTI:
    def __init__(self, klucz: str, klient: httpx.Client | None = None):
        self.klucz = klucz
        self.klient = klient

    def _cel(self, typ: str, wartosc: str) -> tuple[str, str]:
        if typ == "plik":
            return f"/files/{wartosc}", f"{GUI}/file/{wartosc}"
        if typ == "url":
            return f"/urls/{id_url(wartosc)}", f"{GUI}/url/{hashlib.sha256(wartosc.encode()).hexdigest()}"
        if typ == "domena":
            return f"/domains/{wartosc}", f"{GUI}/domain/{wartosc}"
        if typ == "ip":
            return f"/ip_addresses/{wartosc}", f"{GUI}/ip-address/{wartosc}"
        raise ValueError(f"GTI nie obsługuje typu {typ}")

    def sprawdz(self, typ: str, wartosc: str) -> WynikDostawcy:
        sciezka, link = self._cel(typ, wartosc)
        naglowki = {"x-apikey": self.klucz, "x-tool": "miemli"}  # bez x-tool brak gti_assessment
        if self.klient is not None:
            wynik = wykonaj(self.klient, BAZA + sciezka, naglowki, skrot_gti, link)
        else:
            with nowy_klient() as klient:
                wynik = wykonaj(klient, BAZA + sciezka, naglowki, skrot_gti, link)
        if typ == "url" and wynik.surowe:
            # GTI kanonizuje URL przed hashowaniem — link z id z odpowiedzi zamiast sha256 surowego adresu
            wynik.link = f"{GUI}/url/{wynik.surowe.get('data', {}).get('id') or link.rsplit('/', 1)[1]}"
        return wynik
