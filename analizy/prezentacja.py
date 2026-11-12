"""Przekształcenie zapisanego wyniku analizy (JSON) w dane dla szablonów."""

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from django.db.models import Count
from django.utils import timezone

from .models import IOC, Analiza, Wzbogacenie
from .zadania import BLOKADA, DOSTAWCY, skonfigurowany

SEKCJE = [
    ("wiadomosc", "Wiadomość"),
    ("naglowki", "Nagłówki"),
    ("received", "Received"),
    ("zalaczniki", "Załączniki"),
    ("linki", "Linki"),
    ("ioc", "Artefakty"),
]


SEKCJE_DODATKOWE = {"joe": "Joe Sandbox"}  # poza zwykłą listą nawigacji (wyróżniona pozycja w menu)


def _zalaczniki(lista: list[dict]) -> Iterator[dict]:
    for z in lista:
        yield z
        yield from _zalaczniki(z["dzieci"])


def wiadomosci(wynik: dict) -> dict[str, dict]:
    """Wszystkie wiadomości (główna i zagnieżdżone) po id, w kolejności drzewa."""
    wynik_ = {}

    def odwiedz(w: dict) -> None:
        wynik_[w["id"]] = w
        for z in _zalaczniki(w["zalaczniki"]):
            if z["wiadomosc"]:
                odwiedz(z["wiadomosc"])

    odwiedz(wynik["wiadomosc"])
    return wynik_


def liczba_zalacznikow(w: dict) -> int:
    return sum(1 for _ in _zalaczniki(w["zalaczniki"]))


def _czas_utc(tekst) -> datetime | None:
    """Czas bez strefy (nagłówek z „-0000”) traktujemy jako UTC — mieszanie z czasami ze strefą nie może rzucić."""
    try:
        czas = datetime.fromisoformat(tekst) if tekst else None
    except (TypeError, ValueError):
        return None
    return czas.replace(tzinfo=UTC) if czas and czas.tzinfo is None else czas


def _ip_kanoniczne(ip) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except (TypeError, ValueError):
        return ip if isinstance(ip, str) else None


def hopy(received: list[dict]) -> list[dict]:
    """Hopy z opóźnieniem względem poprzedniego (sekundy) — długie przerwy bywają podejrzane."""
    wynik, poprzedni = [], None
    for numer, hop in enumerate(received, start=1):
        czas = _czas_utc(hop.get("czas"))
        hop = {**hop, "ip_kan": _ip_kanoniczne(hop.get("ip"))}
        opoznienie = int((czas - poprzedni).total_seconds()) if czas and poprzedni else None
        wynik.append({**hop, "lp": numer, "czas_dt": czas, "opoznienie": opoznienie})
        poprzedni = czas or poprzedni
    return wynik


def drzewo_ioc(analiza: Analiza) -> list[tuple[IOC, int]]:
    """IOC w kolejności drzewa pochodzenia, z głębokością do wcięcia."""
    wszystkie = list(analiza.ioc.select_related("rodzic"))
    dzieci: dict[int | None, list[IOC]] = {}
    for i in wszystkie:
        dzieci.setdefault(i.rodzic_id, []).append(i)
    wynik: list[tuple[IOC, int]] = []

    def odwiedz(rodzic_id: int | None, glebokosc: int) -> None:
        for i in dzieci.get(rodzic_id, []):
            wynik.append((i, glebokosc))
            odwiedz(i.pk, glebokosc + 1)

    odwiedz(None, 0)
    return wynik


@dataclass
class WidokWzbogacenia:
    # oczekuje | gotowe | brak_danych | limit | blad | nieskonfigurowane | nie_dotyczy
    status: str
    skrot: dict = field(default_factory=dict)
    link: str | None = None
    blad: str = ""
    sprawdzono: datetime | None = None
    ostrzezenie: str = ""  # ostatni dobry wynik pokazany mimo nieudanego odświeżenia


def widoki_wzbogacen(analiza: Analiza) -> tuple[dict[int, dict[str, WidokWzbogacenia]], bool]:
    """Stan wzbogacenia każdego IOC u każdego dostawcy oraz czy coś jest jeszcze w toku."""
    iocs = list(analiza.ioc.all())
    klucze = {
        (i.pk, d): Wzbogacenie.klucz_dla(d, i.typ, i.wartosc)
        for i in iocs for d, typy in DOSTAWCY.items() if i.typ in typy
    }
    wpisy = {w.klucz: w for w in Wzbogacenie.objects.filter(klucz__in=klucze.values())}
    teraz = timezone.now()
    trwa = False
    wynik: dict[int, dict[str, WidokWzbogacenia]] = {}
    for i in iocs:
        wynik[i.pk] = {}
        for d in DOSTAWCY:
            klucz = klucze.get((i.pk, d))
            wpis = wpisy.get(klucz) if klucz else None
            if klucz is None:
                widok = WidokWzbogacenia("nie_dotyczy")
            elif wpis is None:
                widok = WidokWzbogacenia("oczekuje" if skonfigurowany(d) else "nieskonfigurowane")
            elif wpis.status == "oczekuje" and (not wpis.zlecono or teraz - wpis.zlecono >= BLOKADA):
                widok = WidokWzbogacenia("blad", blad="Brak odpowiedzi workera.")
            elif wpis.status in ("limit", "blad") and wpis.skrot:
                widok = WidokWzbogacenia("gotowe", wpis.skrot, wpis.link, "", wpis.sprawdzono,
                                         ostrzezenie=wpis.blad or "Nie udało się odświeżyć.")
            else:
                widok = WidokWzbogacenia(wpis.status, wpis.skrot or {}, wpis.link, wpis.blad, wpis.sprawdzono)
                trwa = trwa or wpis.status == "oczekuje"
            wynik[i.pk][d] = widok
    return wynik, trwa


PODEJRZANE_UWAGI = {"FORMAT_NIEOBSLUGIWANY", "FORMAT_NIEZGODNY", "ZA_DUZO_PIKSELI", "ZA_DUZY_PLIK",
                    "NIETYPOWE_WYMIARY", "USZKODZONY"}


def obrazki_po_sha(wynik: dict) -> dict[str, dict]:
    """Wpisy raportu obrazków z całego drzewa wiadomości, po SHA256 (do tabeli IOC i szczegółów)."""
    return {o["sha256"]: o for w in wiadomosci(wynik).values() for o in w.get("obrazki", [])}


def geo_ip(ioc, wzbogacenia: dict[int, dict[str, WidokWzbogacenia]]) -> dict[str, dict]:
    """Kraj i ASN adresów IP z istniejących wyników wzbogacenia — GTI ma pierwszeństwo, braki uzupełnia Censys."""
    wynik = {}
    for i in ioc:
        if i.typ != "ip":
            continue
        widoki = [wzbogacenia.get(i.pk, {}).get(d) for d in ("gti", "censys")]
        gotowe = [w.skrot for w in widoki if w and w.status == "gotowe"]
        if gotowe:
            pole = lambda nazwa: next((s.get(nazwa) for s in gotowe if s.get(nazwa)), None)  # noqa: E731
            wynik[i.wartosc] = {"stan": "gotowe", "kraj": pole("kraj"), "asn": pole("asn"),
                                "wlasciciel": pole("wlasciciel")}
        elif any(w and w.status == "oczekuje" for w in widoki):
            wynik[i.wartosc] = {"stan": "oczekuje"}
        else:
            wynik[i.wartosc] = {"stan": "brak"}
    return wynik


def inne_analizy(analiza: Analiza) -> dict[int, int]:
    """ioc.pk → w ilu innych analizach wystąpił ten sam artefakt (tylko > 0). Dwa zapytania niezależnie od liczby."""
    wlasne = dict(analiza.ioc.values_list("pk", "skrot"))
    liczby = dict(
        IOC.objects.filter(skrot__in=set(wlasne.values()) - {""}).exclude(analiza=analiza)
        .values("skrot").annotate(n=Count("analiza", distinct=True)).values_list("skrot", "n")
    )
    return {pk: liczby[s] for pk, s in wlasne.items() if liczby.get(s)}


# --- Lista dowodów na ekranie analizy -------------------------------------------------------------

POZIOMY_DOWODOW = [("krytyczne", "Krytyczne"), ("wysokie", "Wysokie"), ("srednie", "Średnie"),
                   ("info", "Informacyjne")]
_KOLEJNOSC = {kod: n for n, (kod, _) in enumerate(POZIOMY_DOWODOW)}

# kod sygnału → (poziom, krótki opis, sekcja); szczegół to opis z analizy
SYGNALY_DOWODOW = {
    "DOMENA_PODOBNA": ("wysokie", "Domena podobna do znanej", "wiadomosc"),
    "REPLY_TO_INNA_DOMENA": ("srednie", "Odpowiedzi trafią do innej domeny", "wiadomosc"),
    "RETURN_PATH_INNA_DOMENA": ("srednie", "Return-Path z innej domeny", "naglowki"),
    "NAZWA_Z_INNYM_ADRESEM": ("srednie", "Nazwa nadawcy udaje inną domenę", "wiadomosc"),
    "DATA_ODLEGLA": ("srednie", "Data wysłania nie zgadza się z serwerami", "received"),
    "DARMOWA_POCZTA": ("info", "Nadawca z darmowej poczty", "wiadomosc"),
}
UWAGI_HOPOW_DOWODOW = {
    "CZAS_WSTECZ": ("srednie", "Czas serwera cofa się"),
    "CZAS_W_PRZYSZLOSCI": ("srednie", "Czas serwera w przyszłości"),
    "DLUGI_POSTOJ": ("info", "Długi postój na serwerze"),
}
_NIEUDANE = ("fail", "softfail", "permerror")


@dataclass
class Dowod:
    poziom: str
    co: str
    gdzie: str
    sekcja: str  # zakładka, w której są szczegóły


def _lista_slow(slowa: list[str]) -> str:
    return slowa[0] if len(slowa) == 1 else ", ".join(slowa[:-1]) + " i " + slowa[-1]


def _linki_slowo(n: int) -> str:
    if n == 1:
        return "Link prowadzi gdzie indziej, niż mówi tekst"
    forma = "linki prowadzą" if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14) else "linków prowadzi"
    return f"{n} {forma} gdzie indziej, niż mówi tekst"


def _dowody_gti(ioc, wzbogacenia) -> Iterator[Dowod]:
    from mailcore.rozbrajanie import rozbroj

    from .templatetags.miemli import nowa_domena, wiek

    for i, _ in ioc:
        g = wzbogacenia.get(i.pk, {}).get("gti")
        if g is None or g.status != "gotowe":
            continue
        s = g.skrot or {}
        nazwa = (i.etykieta or i.wartosc) if i.typ == "plik" else rozbroj(i.typ, i.wartosc)
        wykrycia = s.get("wykrycia")
        szczegol = [f"{wykrycia[0]}/{wykrycia[1]} wykryć"] if wykrycia else []
        rodzic = getattr(i, "rodzic", None)
        if i.typ == "plik" and rodzic is not None and rodzic.typ == "plik":
            szczegol.append(f"w {rodzic.etykieta or rodzic.wartosc}")
        gdzie = ", ".join(szczegol) or "werdykt GTI"
        if s.get("werdykt") == "zlosliwy":
            yield Dowod("krytyczne", f"{nazwa}: złośliwy w GTI", gdzie, "ioc")
        elif s.get("werdykt") == "podejrzany":
            yield Dowod("wysokie", f"{nazwa}: podejrzany w GTI", gdzie, "ioc")
        elif wykrycia and wykrycia[0] > 0:
            yield Dowod("srednie", f"{nazwa}: pojedyncze wykrycia w GTI", gdzie, "ioc")
        if i.typ == "domena" and nowa_domena(s.get("utworzono")):
            yield Dowod("wysokie", f"Domena {nazwa} ma {wiek(s['utworzono'])}", "data rejestracji z GTI", "ioc")


def dowody(w: dict, a: dict, ioc, wzbogacenia) -> list[Dowod]:
    """Sygnały analizy wiadomości i wyniki GTI artefaktów jako lista dowodów, od najgroźniejszego."""
    from mailcore.rozbrajanie import rozbroj

    wynik: list[Dowod] = list(_dowody_gti(ioc, wzbogacenia))

    auth = a.get("uwierzytelnienie") or {}
    nieudane = [n.upper() for n in ("spf", "dkim", "dmarc") if auth.get(n) in _NIEUDANE]
    brak = [n.upper() for n in ("spf", "dkim", "dmarc") if auth.get(n) in (None, "", "none")]
    if nieudane:
        opis = ", ".join(f"{n.upper()} {auth.get(n) or 'brak'}" for n in ("spf", "dkim", "dmarc"))
        wynik.append(Dowod("wysokie", f"{_lista_slow(nieudane)} nie {'przeszły' if len(nieudane) > 1 else 'przeszedł'}",
                           opis, "naglowki"))
    if brak:
        wynik.append(Dowod("info", f"Brak wyniku: {', '.join(brak)}", "nagłówek Authentication-Results", "naglowki"))

    for z in _zalaczniki(w.get("zalaczniki", [])):
        if z.get("zaszyfrowany"):
            wynik.append(Dowod("wysokie", "Zaszyfrowany załącznik bez hasła", z["nazwa"], "zalaczniki"))

    podejrzane = [o for o in w.get("obrazki", []) if any(u["kod"] in PODEJRZANE_UWAGI for u in o.get("uwagi", []))]
    if podejrzane:
        wynik.append(Dowod("wysokie", "Nietypowe obrazki w wiadomości",
                           ", ".join(o["nazwa"] for o in podejrzane), "wiadomosc"))

    for s in a.get("sygnaly", []):
        poziom, co, sekcja = SYGNALY_DOWODOW.get(s["kod"], ("srednie", s["opis"], "wiadomosc"))
        wynik.append(Dowod(poziom, co, "" if co == s["opis"] else s["opis"], sekcja))

    niezgodne = [l for l in a.get("linki", []) if l.get("niezgodny")]
    if niezgodne:
        wynik.append(Dowod("srednie", _linki_slowo(len(niezgodne)),
                           ", ".join(rozbroj("url", l["docelowy"]) for l in niezgodne[:3]), "linki"))

    for numer, hop in enumerate(a.get("received", []), start=1):
        for u in hop.get("uwagi", []):
            if u["kod"] in UWAGI_HOPOW_DOWODOW:
                poziom, co = UWAGI_HOPOW_DOWODOW[u["kod"]]
                wynik.append(Dowod(poziom, co, f"Serwer {numer}: {u['opis']}", "received"))

    for o in w.get("ostrzezenia", []):
        wynik.append(Dowod("info", o["opis"], "ostrzeżenie parsera", "zalaczniki"))

    return sorted(wynik, key=lambda d: _KOLEJNOSC[d.poziom])


def grupy_dowodow(lista: list[Dowod]) -> list[tuple[str, str, list[Dowod]]]:
    return [(kod, nazwa, grupa) for kod, nazwa in POZIOMY_DOWODOW
            if (grupa := [d for d in lista if d.poziom == kod])]
