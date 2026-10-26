"""Budowa listy IOC z relacjami pochodzenia (drzewo przez rodzic_id)."""

import email.utils
import ipaddress
import re
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ..archiwa import jest_archiwum
from ..domeny import domena_adresu, normalizuj
from ..model import Wiadomosc, Zalacznik
from ..tekst import tekst_z_html
from .qr import odczytaj_qr

if TYPE_CHECKING:
    from . import AnalizaWiadomosci

MAKS_OBRAZOW_QR = 20
NAGLOWKI_NADAWCY = ("From", "Reply-To", "Return-Path", "Sender")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class IOC:
    id: int
    typ: str  # "plik" | "url" | "domena" | "ip" | "email"
    wartosc: str
    rodzic_id: int | None
    zrodlo: str  # "naglowek" | "tresc" | "zalacznik" | "qr"
    etykieta: str | None = None
    hashe: dict[str, str] | None = None


def _publiczny_ip(wartosc: str) -> str | None:
    try:
        ip = ipaddress.ip_address(wartosc)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


class _Budowniczy:
    def __init__(self, wiadomosci: dict[str, "AnalizaWiadomosci"], ignorowane: frozenset[str]):
        self.wiadomosci = wiadomosci
        self.ignorowane = ignorowane
        self.lista: list[IOC] = []
        self.indeks: dict[tuple[str, str], int] = {}
        self.kolejka: deque[tuple[Wiadomosc, int | None]] = deque()
        self.qr: dict[str, list[str]] = {}  # sha256 → odczytane kody

    def ignorowana(self, domena: str) -> bool:
        return any(domena == d or domena.endswith("." + d) for d in self.ignorowane)

    def dodaj(self, typ, wartosc, rodzic_id, zrodlo, etykieta=None, hashe=None) -> int:
        klucz = (typ, wartosc)
        if klucz not in self.indeks:
            ioc = IOC(len(self.lista) + 1, typ, wartosc, rodzic_id, zrodlo, etykieta, hashe)
            self.lista.append(ioc)
            self.indeks[klucz] = ioc.id
        return self.indeks[klucz]

    def domena_lub_ip(self, host: str, rodzic_id: int, zrodlo: str) -> None:
        ip = _publiczny_ip(host)
        if ip:
            self.dodaj("ip", ip, rodzic_id, zrodlo)
        elif not re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
            self.dodaj("domena", normalizuj(host), rodzic_id, zrodlo)

    def url(self, url: str, etykieta: str | None, rodzic_id: int | None, zrodlo: str) -> None:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            return
        if not host or self.ignorowana(normalizuj(host)):
            return
        if _publiczny_ip(host) is None and re.fullmatch(r"[\d.]+", host):
            return  # URL do prywatnego IP
        url_id = self.dodaj("url", url, rodzic_id, zrodlo, etykieta)
        self.domena_lub_ip(host, url_id, zrodlo)

    def wiadomosc(self, w: Wiadomosc, rodzic_id: int | None) -> None:
        analiza = self.wiadomosci[w.id]
        for nazwa in NAGLOWKI_NADAWCY:
            for wartosc in w.naglowki_wszystkie(nazwa):
                adres = email.utils.parseaddr(wartosc)[1].lower()
                domena = domena_adresu(adres)
                if not domena or self.ignorowana(domena):
                    continue
                email_id = self.dodaj("email", adres, rodzic_id, "naglowek")
                self.dodaj("domena", domena, email_id, "naglowek")
        for hop in analiza.received:
            ip = hop.ip and _publiczny_ip(hop.ip)
            if ip:
                self.dodaj("ip", ip, rodzic_id, "naglowek")
        for link in analiza.linki:
            self.url(link.docelowy, link.tekst, rodzic_id, "tresc")
        tresc = " ".join(filter(None, [w.tekst, w.html and tekst_z_html(w.html)]))
        for kandydat in _IPV4.findall(tresc):
            ip = _publiczny_ip(kandydat)
            if ip:
                self.dodaj("ip", ip, rodzic_id, "tresc")
        for z in w.zalaczniki:
            self.zalacznik(z, rodzic_id)

    def zalacznik(self, z: Zalacznik, rodzic_id: int | None) -> None:
        plik_id = self.dodaj(
            "plik", z.sha256, rodzic_id, "zalacznik", z.nazwa,
            {"md5": z.md5, "sha1": z.sha1, "sha256": z.sha256},
        )
        if z.typ_mime.startswith("image/"):
            if z.sha256 not in self.qr and len(self.qr) < MAKS_OBRAZOW_QR:
                self.qr[z.sha256] = odczytaj_qr(z.dane)
            for tresc in self.qr.get(z.sha256, []):
                if re.match(r"https?://", tresc, re.IGNORECASE):
                    self.url(tresc, None, plik_id, "qr")
        if jest_archiwum(z):
            for dziecko in z.dzieci:
                self.zalacznik(dziecko, plik_id)
        if z.wiadomosc is not None:
            self.kolejka.append((z.wiadomosc, plik_id))

    def zbuduj(self, w: Wiadomosc) -> list[IOC]:
        self.kolejka.append((w, None))
        while self.kolejka:
            self.wiadomosc(*self.kolejka.popleft())
        return self.lista


def zbuduj_ioc(
    w: Wiadomosc, wiadomosci: dict[str, "AnalizaWiadomosci"], ignorowane_domeny: frozenset[str]
) -> list[IOC]:
    return _Budowniczy(wiadomosci, ignorowane_domeny).zbuduj(w)
