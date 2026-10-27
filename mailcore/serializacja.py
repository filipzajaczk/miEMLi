"""Wynik parsowania i analizy jako JSON do zapisu w bazie. Bez bajtów załączników."""

from dataclasses import asdict
from datetime import datetime

from .analiza import WynikAnalizy
from .html_bezpieczny import bezpieczny_html
from .model import Wiadomosc, Zalacznik


def _data(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _zalacznik(z: Zalacznik, obrazki) -> dict:
    return {
        "nazwa": z.nazwa,
        "typ_mime": z.typ_mime,
        "rozmiar": z.rozmiar,
        "md5": z.md5,
        "sha1": z.sha1,
        "sha256": z.sha256,
        "content_id": z.content_id,
        "inline": z.inline,
        "zaszyfrowany": z.zaszyfrowany,
        "haslo": z.haslo,
        "dzieci": [_zalacznik(d, obrazki) for d in z.dzieci],
        "wiadomosc": _wiadomosc(z.wiadomosc, obrazki) if z.wiadomosc else None,
    }


def _wiadomosc(w: Wiadomosc, obrazki) -> dict:
    wlasne = (obrazki or {}).get(w.id, [])
    mapa = {o.wpis["content_id"]: (o.png if o.png is not None else o.wpis.get("powod", ""))
            for o in wlasne if o.wpis["content_id"]}
    return {
        "id": w.id,
        "naglowki": [list(p) for p in w.naglowki],
        "temat": w.temat,
        "od": w.od,
        "do": w.do,
        "data": _data(w.data),
        "tekst": w.tekst,
        "html_bezpieczny": bezpieczny_html(w.html, w.zalaczniki, mapa) if w.html else None,
        "obrazki": [o.wpis for o in wlasne],
        "zalaczniki": [_zalacznik(z, obrazki) for z in w.zalaczniki],
        "ostrzezenia": [asdict(o) for o in w.ostrzezenia],
    }


def _analiza(a) -> dict:
    wynik = asdict(a)
    for hop in wynik["received"]:
        hop["czas"] = _data(hop["czas"])
    return wynik


def bez_nul(obj):
    """Postgres nie przyjmuje \x00 w tekście ani w jsonb."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {bez_nul(k): bez_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [bez_nul(v) for v in obj]
    return obj


def do_json(w: Wiadomosc, wynik: WynikAnalizy, obrazki: dict | None = None) -> dict:
    """obrazki: wynik piaskownica.obrazki.przetworz_obrazki (klucz = id wiadomości)."""
    return bez_nul({
        "wiadomosc": _wiadomosc(w, obrazki),
        "analiza": {id: _analiza(a) for id, a in wynik.wiadomosci.items()},
        "ioc": [asdict(i) for i in wynik.ioc],
    })
