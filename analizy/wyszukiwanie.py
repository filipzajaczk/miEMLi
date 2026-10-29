"""Wyszukiwarka analiz: „czy ten artefakt już był u nas?”.

Zapytanie nie trafia do audytu ani logów — bywa adresem e-mail ofiary.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import render

from mailcore.rozbrajanie import rozbroj

from .models import IOC, Analiza

MAKS_WEJSCIE = 2048
MAKS_WYNIKOW = 200
MIN_TEKST = 3
_UZBROJENIE = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.I), "."),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
]
_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_DOMENA = re.compile(r"(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}")
_STEROWANIE = re.compile(r"[\x00-\x1f\x7f]")


def uzbroj(tekst: str) -> str:
    """Zamienia zapis rozbrojony (z raportów) z powrotem na zwykły."""
    tekst = _STEROWANIE.sub("", tekst or "")[:MAKS_WEJSCIE]
    for wzorzec, zamiana in _UZBROJENIE:
        tekst = wzorzec.sub(zamiana, tekst)
    return tekst.strip()


def _domena(tekst: str) -> str | None:
    try:
        ascii_ = tekst.lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ascii_ if _DOMENA.fullmatch(ascii_) else None


def rozpoznaj(tekst: str) -> tuple[str, str]:
    t = tekst.strip()
    if _HASH.fullmatch(t.lower()):
        return "hash", t.lower()
    try:
        return "ip", str(ipaddress.ip_address(t))
    except ValueError:
        pass
    if _EMAIL.fullmatch(t):
        return "email", t.lower()
    if t.lower().startswith(("http://", "https://")):
        return "url", t
    if " " not in t and "." in t and (d := _domena(t)):
        return "domena", d
    if len(t) < MIN_TEKST:
        return "za_krotki", t
    return "tekst", t


@dataclass
class WynikWyszukiwania:
    analizy: list[Analiza] = field(default_factory=list)
    dopasowania: dict[int, str] = field(default_factory=dict)
    obcieto: bool = False
    komunikat: str = ""


def _artefakty(warunek: Q) -> dict[int, str]:
    """analiza_id → opis pierwszego dopasowanego artefaktu (rozbrojony)."""
    wynik: dict[int, str] = {}
    for analiza_id, typ, wartosc in IOC.objects.filter(warunek).values_list("analiza_id", "typ", "wartosc"):
        opis = {"plik": "plik", "email": "e-mail"}.get(typ, typ)
        wynik.setdefault(analiza_id, f"{opis}: {rozbroj(typ, wartosc)}")
    return wynik


def _domeny(d: str) -> Q:
    return Q(typ="domena") & (Q(wartosc=d) | Q(wartosc__endswith="." + d))


def szukaj(tekst: str) -> WynikWyszukiwania:
    rodzaj, wartosc = rozpoznaj(uzbroj(tekst))
    if rodzaj == "za_krotki":
        return WynikWyszukiwania(komunikat="Wpisz co najmniej 3 znaki.")
    dopasowania: dict[int, str] = {}
    if rodzaj == "hash":
        dopasowania = _artefakty(Q(typ="plik") & (Q(wartosc=wartosc) | Q(hashe__md5=wartosc)
                                                  | Q(hashe__sha1=wartosc)))
        for pk in Analiza.objects.filter(sha256=wartosc).values_list("pk", flat=True):
            dopasowania.setdefault(pk, "plik .eml/.msg")
    elif rodzaj in ("ip", "email"):
        dopasowania = _artefakty(Q(typ=rodzaj, wartosc=wartosc))
    elif rodzaj == "url":
        dopasowania = _artefakty(Q(typ="url", wartosc=wartosc))
        if host := _domena(re.sub(r"^https?://", "", wartosc, flags=re.I).split("/")[0].split(":")[0]):
            for pk, opis in _artefakty(_domeny(host)).items():
                dopasowania.setdefault(pk, opis)
    elif rodzaj == "domena":
        dopasowania = _artefakty(_domeny(wartosc))
    if rodzaj in ("domena", "tekst"):
        # „faktura.eml” wygląda jak domena, a bywa nazwą pliku — szukamy też w tekście
        for pole, opis in (("temat_wiadomosci", "temat"), ("nazwa_pliku", "nazwa pliku"), ("notatka", "komentarz")):
            for pk in Analiza.objects.filter(**{f"{pole}__icontains": wartosc}).values_list("pk", flat=True):
                dopasowania.setdefault(pk, opis)
    analizy = list(Analiza.objects.filter(pk__in=dopasowania).select_related("utworzyl").defer("wynik")
                   .order_by("-utworzono", "-pk")[:MAKS_WYNIKOW + 1])
    return WynikWyszukiwania(analizy[:MAKS_WYNIKOW], dopasowania, len(analizy) > MAKS_WYNIKOW)


@login_required
def szukaj_widok(request):
    q = request.GET.get("q", "")[:MAKS_WEJSCIE]
    wynik = szukaj(q) if q.strip() else WynikWyszukiwania()
    return render(request, "analizy/szukaj.html", {"q": q, "wynik": wynik})
