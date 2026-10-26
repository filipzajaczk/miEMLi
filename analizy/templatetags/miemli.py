from django import template

from mailcore.rozbrajanie import rozbroj as _rozbroj

register = template.Library()


@register.filter
def rozbroj(wartosc, typ):
    return _rozbroj(typ, wartosc) if wartosc else wartosc


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
