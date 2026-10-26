import re
from dataclasses import dataclass

from ..model import Wiadomosc


@dataclass
class Uwierzytelnienie:
    spf: str | None
    dkim: str | None
    dmarc: str | None


def _wynik(naglowek: str, mechanizm: str) -> str | None:
    znaleziony = re.search(rf"\b{mechanizm}\s*=\s*([a-z]+)", naglowek, re.IGNORECASE)
    return znaleziony.group(1).lower() if znaleziony else None


def sprawdz_uwierzytelnienie(w: Wiadomosc) -> Uwierzytelnienie:
    """Z najwyższego Authentication-Results — dodanego przez nasz serwer odbiorczy."""
    naglowek = w.naglowek("Authentication-Results") or ""
    return Uwierzytelnienie(_wynik(naglowek, "spf"), _wynik(naglowek, "dkim"), _wynik(naglowek, "dmarc"))
