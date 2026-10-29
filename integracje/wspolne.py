"""Wspólny klient HTTP i mapowanie odpowiedzi API na statusy wzbogacenia."""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

STATUSY = ("oczekuje", "gotowe", "brak_danych", "limit", "blad")
USER_AGENT = "miemli/1.0"  # Censys (Cloudflare) blokuje domyślny User-Agent Pythona
TIMEOUT = 20.0


@dataclass
class WynikDostawcy:
    status: str  # "gotowe" | "brak_danych" | "limit" | "blad"
    skrot: dict = field(default_factory=dict)
    surowe: dict | None = None
    link: str | None = None
    blad: str = ""
    ponawiac: bool = False


def nowy_klient() -> httpx.Client:
    return httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)


def wykonaj(
    klient: httpx.Client,
    url: str,
    naglowki: dict,
    parsuj: Callable[[dict], dict],
    link: str | None,
    params: dict | None = None,
) -> WynikDostawcy:
    try:
        odp = klient.get(url, headers=naglowki, params=params)
    except (httpx.InvalidURL, httpx.UnsupportedProtocol, ValueError):
        # adres zbudowany z artefaktu (np. ze znakiem sterującym) — ponowienie nic nie da
        return WynikDostawcy("blad", link=link, blad="Nieprawidłowy adres.")
    except httpx.TimeoutException:
        return WynikDostawcy("blad", link=link, blad="Przekroczono czas odpowiedzi.", ponawiac=True)
    except httpx.HTTPError:
        return WynikDostawcy("blad", link=link, blad="Błąd połączenia.", ponawiac=True)

    kod = odp.status_code
    if kod in (400, 404):  # 400: dostawca odrzuca wskaźnik (np. domena z nieistniejącą TLD)
        return WynikDostawcy("brak_danych", link=link)
    if kod == 429:
        return WynikDostawcy("limit", link=link, blad="Przekroczono limit zapytań API.", ponawiac=True)
    if kod in (401, 403):
        return WynikDostawcy(
            "blad", link=link, blad=f"Odmowa dostępu (HTTP {kod}) — sprawdź klucz lub uprawnienia."
        )
    if kod >= 500:
        return WynikDostawcy("blad", link=link, blad=f"Błąd serwera (HTTP {kod}).", ponawiac=True)
    if kod != 200:
        return WynikDostawcy("blad", link=link, blad=f"Nieoczekiwana odpowiedź (HTTP {kod}).")
    try:
        dane = odp.json()
        return WynikDostawcy("gotowe", skrot=parsuj(dane), surowe=dane, link=link)
    except Exception:
        logger.warning("Nieprawidłowa odpowiedź API (%s)", url.split("?")[0].rsplit("/", 2)[0])
        return WynikDostawcy("blad", link=link, blad="Nieprawidłowa odpowiedź API.")
