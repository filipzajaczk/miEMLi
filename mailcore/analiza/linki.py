import base64
import re
import string
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from bs4 import BeautifulSoup

from ..domeny import domena_bazowa
from ..model import Wiadomosc
from ..tekst import tekst_z_html

MAKS_LINKOW = 500
_URL = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)
_WYGLADA_JAK_ADRES = re.compile(
    r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$", re.IGNORECASE
)
_PROOFPOINT_V3 = re.compile(r"/v3/__(?P<url>.+?)__;(?P<bajty>[^!]*)!")
_V3_TOKEN = re.compile(r"\*(\*.)?")
_V3_DLUGOSCI = {znak: i + 2 for i, znak in enumerate(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_")}


@dataclass
class Link:
    url: str
    docelowy: str
    tekst: str | None
    niezgodny: bool
    zrodlo: str  # "html" | "tekst"


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _proofpoint_v3(url: str) -> str | None:
    znaleziony = _PROOFPOINT_V3.search(url)
    if not znaleziony:
        return None
    bajty = znaleziony.group("bajty")
    try:
        znaki = base64.urlsafe_b64decode(bajty + "=" * (-len(bajty) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    pozycja = 0

    def podmien(token: re.Match) -> str:
        nonlocal pozycja
        dlugosc = _V3_DLUGOSCI.get(token.group(1)[-1], 1) if token.group(1) else 1
        fragment = znaki[pozycja:pozycja + dlugosc]
        pozycja += dlugosc
        return fragment

    return _V3_TOKEN.sub(podmien, znaleziony.group("url"))


def rozpakuj_przekierowanie(url: str) -> str | None:
    """Microsoft SafeLinks i Proofpoint URL Defense (v2, v3) → prawdziwy adres."""
    host = (_host(url) or "").lower()
    if host.endswith("safelinks.protection.outlook.com"):
        cel = parse_qs(urlsplit(url).query).get("url")
        return cel[0] if cel else None
    if host == "urldefense.proofpoint.com" and "/v2/" in url:
        cel = parse_qs(urlsplit(url).query).get("u")
        if not cel:
            return None
        return unquote(cel[0].replace("-", "%").replace("_", "/"))
    if host == "urldefense.com":
        return _proofpoint_v3(url)
    return None


def _docelowy(url: str) -> str:
    for _ in range(3):  # przekierowania bywają zagnieżdżone
        cel = rozpakuj_przekierowanie(url)
        if not cel:
            break
        url = cel
    return url


def _niezgodny(tekst: str | None, docelowy: str) -> bool:
    if not tekst:
        return False
    znaleziony = _WYGLADA_JAK_ADRES.match(tekst.strip())
    host = _host(docelowy)
    if not znaleziony or not host:
        return False
    return domena_bazowa(znaleziony.group(1)) != domena_bazowa(host)


def _urle_z_tekstu(tekst: str) -> list[str]:
    return [u.rstrip(".,;:!?") for u in _URL.findall(tekst)]


def wyciagnij_linki(w: Wiadomosc) -> list[Link]:
    wynik: list[Link] = []
    widziane: set[str] = set()

    def dodaj(url: str, tekst: str | None, zrodlo: str) -> None:
        if len(wynik) >= MAKS_LINKOW or not re.match(r"https?://", url, re.IGNORECASE):
            return
        klucz = url if zrodlo == "tekst" else f"{url}\x00{tekst}"
        if klucz in widziane or (zrodlo == "tekst" and any(l.url == url for l in wynik)):
            return
        widziane.add(klucz)
        docelowy = _docelowy(url)
        wynik.append(Link(url, docelowy, tekst, _niezgodny(tekst, docelowy), zrodlo))

    if w.html:
        for a in BeautifulSoup(w.html, "html.parser").find_all("a", href=True):
            dodaj(a["href"].strip(), a.get_text(" ", strip=True) or None, "html")
        for url in _urle_z_tekstu(tekst_z_html(w.html)):
            dodaj(url, None, "tekst")
    if w.tekst:
        for url in _urle_z_tekstu(w.tekst):
            dodaj(url, None, "tekst")
    return wynik
