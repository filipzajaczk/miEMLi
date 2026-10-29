import re

from django import template

from mailcore.rozbrajanie import rozbroj as _rozbroj

register = template.Library()


@register.filter
def rozbroj(wartosc, typ):
    return _rozbroj(typ, wartosc) if wartosc else wartosc


_HTTP = re.compile(r"http", re.I)
_DOMENOPODOBNE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


@register.filter
def rozbroj_tekst(wartosc):
    """Dowolny tekst od dostawcy (nazwy plików, tagi): http → hxxp, kropki w nazwach domenopodobnych → [.]."""
    if not isinstance(wartosc, str):
        wartosc = str(wartosc)
    wartosc = _HTTP.sub("hxxp", wartosc)
    return _DOMENOPODOBNE.sub(lambda m: m.group(0).replace(".", "[.]"), wartosc)


@register.filter
def rozbrojony(ioc):
    return _rozbroj(ioc.typ, ioc.wartosc)


@register.filter
def klasa_auth(wynik):
    if wynik == "pass":
        return "ok"
    if wynik in ("fail", "softfail", "permerror"):
        return "bad"
    return "warn"


@register.filter
def rozmiar(bajty):
    for jednostka in ("B", "KB", "MB"):
        if bajty < 1024 or jednostka == "MB":
            return f"{bajty:.0f} {jednostka}" if jednostka == "B" else f"{bajty:.1f} {jednostka}"
        bajty /= 1024


@register.filter
def klucz(slownik, nazwa):
    return slownik.get(nazwa)


@register.filter
def naglowek(w, nazwa):
    nazwa = nazwa.lower()
    return next((v for k, v in w["naglowki"] if k.lower() == nazwa), None)


@register.filter
def iso_data(wartosc):
    from datetime import datetime

    try:
        return datetime.fromisoformat(wartosc) if wartosc else None
    except ValueError:
        return None


@register.filter
def mechanizmy(uwierzytelnienie):
    return [(nazwa.upper(), uwierzytelnienie.get(nazwa)) for nazwa in ("spf", "dkim", "dmarc")]


WERDYKTY_KLASY = {"zlosliwy": "bad", "podejrzany": "warn", "nieszkodliwy": "ok"}
WERDYKTY_OPISY = {"zlosliwy": "złośliwy", "podejrzany": "podejrzany", "nieszkodliwy": "nieszkodliwy"}


@register.filter
def klasa_werdyktu(werdykt):
    return WERDYKTY_KLASY.get(werdykt, "neutral")


@register.filter
def opis_werdyktu(werdykt):
    return WERDYKTY_OPISY.get(werdykt, "niewykryty")


def _dni(epoch) -> int | None:
    import time

    if epoch is None:
        return None
    try:
        dni = int((time.time() - float(epoch)) // 86400)
    except (TypeError, ValueError, OverflowError):
        return None
    return dni if dni >= 0 else None  # data z przyszłości — błąd danych, nie „nowa domena”


@register.filter
def wiek(epoch) -> str:
    dni = _dni(epoch)
    if dni is None:
        return ""
    if dni < 30:
        return "1 dzień" if dni == 1 else f"{dni} dni"
    if dni < 365:
        return f"{dni // 30} mies."
    lata = dni // 365
    if lata == 1:
        return "1 rok"
    if lata % 10 in (2, 3, 4) and lata % 100 not in (12, 13, 14):
        return f"{lata} lata"
    return f"{lata} lat"


@register.filter
def nowa_domena(epoch) -> bool:
    dni = _dni(epoch)
    return dni is not None and dni < 30


@register.filter
def pierwsze(lista, n):
    return list(lista or [])[: int(n)]


@register.filter
def reszta(lista, n):
    return max(len(lista or []) - int(n), 0)


@register.filter
def z_epoch(epoch):
    from datetime import UTC, datetime

    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


@register.filter
def z_archiwum(ioc) -> bool:
    """Plik, którego rodzicem jest inny plik niebędący wiadomością — czyli wyodrębniony z archiwum."""
    rodzic = ioc.rodzic
    if ioc.typ != "plik" or rodzic is None or rodzic.typ != "plik":
        return False
    return not (rodzic.etykieta or "").lower().endswith((".eml", ".msg"))


@register.filter
def pliki(n) -> str:
    n = int(n)
    if n == 1:
        return "1 plik"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} pliki"
    return f"{n} plików"


UWAGI_OBRAZKOW = {
    "FORMAT_NIEOBSLUGIWANY": "format nieobsługiwany", "FORMAT_NIEZGODNY": "format niezgodny",
    "ZA_DUZO_PIKSELI": "za dużo pikseli", "ZA_DUZY_PLIK": "za duży plik", "NIETYPOWE_WYMIARY": "nietypowe wymiary",
    "ANIMACJA": "animacja", "USZKODZONY": "uszkodzony", "LIMIT_LICZBY": "limit liczby",
    "PRZESKALOWANY": "przeskalowany",
}


@register.filter
def opis_uwagi_obrazka(kod):
    return UWAGI_OBRAZKOW.get(kod, kod)


@register.filter
def klasa_uwagi_obrazka(kod):
    from analizy.prezentacja import PODEJRZANE_UWAGI

    return "warn" if kod in PODEJRZANE_UWAGI else "neutral"


@register.filter
def podejrzane_obrazki(obrazki) -> list:
    from analizy.prezentacja import PODEJRZANE_UWAGI

    return [o for o in obrazki or [] if any(u["kod"] in PODEJRZANE_UWAGI for u in o.get("uwagi", []))]


@register.filter
def pierwsza_podejrzana_uwaga(obraz):
    from analizy.prezentacja import PODEJRZANE_UWAGI

    return next((u["kod"] for u in (obraz or {}).get("uwagi", []) if u["kod"] in PODEJRZANE_UWAGI), None)


@register.filter
def klasa_werdyktu_analityka(kod):
    return {"phishing": "bad", "spam": "warn", "czysty": "ok", "do_weryfikacji": "neutral"}.get(kod, "neutral")
