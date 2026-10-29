import email.utils
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from ..model import Wiadomosc
from .podszywanie import Sygnal

CZAS_WSTECZ = timedelta(minutes=5)
DLUGI_POSTOJ = timedelta(hours=1)
TOLERANCJA_PRZYSZLOSCI = timedelta(minutes=15)
DATA_ODLEGLA = timedelta(hours=24)

_OD = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_PRZEZ = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_IP = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")


@dataclass
class Hop:
    od: str | None
    przez: str | None
    ip: str | None
    czas: datetime | None
    uwagi: list[Sygnal] = field(default_factory=list)


def _utc(czas: datetime | None) -> datetime | None:
    """Czas bez strefy (np. „-0000”) traktujemy jako UTC — inaczej porównania rzucają TypeError."""
    if czas is None:
        return None
    return czas.replace(tzinfo=UTC) if czas.tzinfo is None else czas


def _minuty(roznica: timedelta) -> int:
    return int(roznica.total_seconds() // 60)


def _uwagi(hop: Hop, poprzedni: datetime | None, teraz: datetime) -> None:
    czas = _utc(hop.czas)
    if czas is None:
        hop.uwagi.append(Sygnal("BRAK_CZASU", "Brak czytelnego czasu."))
    if not hop.ip:
        hop.uwagi.append(Sygnal("BRAK_IP", "Brak adresu IP."))
    if czas is None:
        return
    if poprzedni is not None and poprzedni - czas > CZAS_WSTECZ:
        hop.uwagi.append(Sygnal("CZAS_WSTECZ", f"Czas cofa się o {_minuty(poprzedni - czas)} min względem "
                                               "poprzedniego serwera — wpis sfałszowany albo zły zegar."))
    if poprzedni is not None and czas - poprzedni > DLUGI_POSTOJ:
        minuty = _minuty(czas - poprzedni)
        hop.uwagi.append(Sygnal("DLUGI_POSTOJ", f"Postój {minuty // 60} h {minuty % 60} min na poprzednim serwerze."))
    if czas - teraz > TOLERANCJA_PRZYSZLOSCI:
        hop.uwagi.append(Sygnal("CZAS_W_PRZYSZLOSCI", "Czas w przyszłości — nagłówek sfałszowany albo zły zegar."))


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


def sciezka_received(w: Wiadomosc, teraz: datetime | None = None) -> list[Hop]:
    """Najstarszy hop pierwszy (nagłówki Received są dopisywane na górze), z anomaliami czasu."""
    teraz = _utc(teraz) or datetime.now(UTC)
    hopy = [_hop(n) for n in reversed(w.naglowki_wszystkie("Received"))]
    poprzedni = None
    for hop in hopy:
        _uwagi(hop, poprzedni, teraz)
        poprzedni = _utc(hop.czas) or poprzedni
    return hopy


def sygnaly_czasu(w: Wiadomosc, hopy: list[Hop]) -> list[Sygnal]:
    """Data wysłania (Date) daleko od pierwszego serwera — mail przygotowany wcześniej albo sfałszowana data."""
    pierwszy = next((_utc(h.czas) for h in hopy if h.czas), None)
    try:
        data = _utc(email.utils.parsedate_to_datetime(w.naglowek("Date") or ""))
    except (TypeError, ValueError, IndexError):
        data = None
    if pierwszy is None or data is None or abs(data - pierwszy) <= DATA_ODLEGLA:
        return []
    godziny = int(abs(data - pierwszy).total_seconds() // 3600)
    return [Sygnal("DATA_ODLEGLA", f"Data wysłania różni się o {godziny} h od pierwszego serwera.")]
