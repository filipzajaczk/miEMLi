import email.utils
import re
from dataclasses import dataclass
from datetime import datetime

from ..model import Wiadomosc

_OD = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_PRZEZ = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_IP = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")


@dataclass
class Hop:
    od: str | None
    przez: str | None
    ip: str | None
    czas: datetime | None


def _czas(naglowek: str) -> datetime | None:
    if ";" not in naglowek:
        return None
    try:
        return email.utils.parsedate_to_datetime(naglowek.rsplit(";", 1)[1].strip())
    except (TypeError, ValueError, IndexError):
        return None


def _hop(naglowek: str) -> Hop:
    przed_czasem = naglowek.rsplit(";", 1)[0] if ";" in naglowek else naglowek
    od = _OD.search(przed_czasem)
    przez = _PRZEZ.search(przed_czasem)
    ip = _IP.search(przed_czasem.split(" by ", 1)[0])
    return Hop(
        od=od.group(1) if od else None,
        przez=przez.group(1).rstrip(";") if przez else None,
        ip=ip.group(1) if ip else None,
        czas=_czas(naglowek),
    )


def sciezka_received(w: Wiadomosc) -> list[Hop]:
    """Najstarszy hop pierwszy (nagłówki Received są dopisywane na górze)."""
    return [_hop(n) for n in reversed(w.naglowki_wszystkie("Received"))]
