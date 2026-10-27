"""Obrazki z wiadomości: rozpoznanie formatu (bez dekodowania), raport nietypowych obrazków
i przekodowanie do czystego PNG. Do przeglądarki analityka trafiają tylko obrazy wygenerowane tutaj."""

import io
import warnings
from collections.abc import Iterator
from dataclasses import dataclass

from PIL import Image

from mailcore.model import Wiadomosc, Zalacznik

DOZWOLONE = ("PNG", "JPEG", "GIF", "BMP")
MAKS_PLIK = 10 * 1024 * 1024
MAKS_PIKSELI = 20_000_000
MAKS_BOK = 10_000
MAKS_PROPORCJE = 50
SZEROKOSC_WYJSCIA = 1600
MAKS_PNG = 2 * 1024 * 1024
MAKS_LICZBA = 20

OPISY = {
    "FORMAT_NIEOBSLUGIWANY": "Format obrazka nie jest obsługiwany ({format}) — nie został zdekodowany.",
    "FORMAT_NIEZGODNY": "Format pliku ({format}) jest inny niż zadeklarowany ({deklaracja}).",
    "ZA_DUZO_PIKSELI": "Obraz ma ponad 20 Mpx.",
    "ZA_DUZY_PLIK": "Plik obrazka jest zbyt duży.",
    "NIETYPOWE_WYMIARY": "Nietypowe wymiary obrazka.",
    "ANIMACJA": "Animacja — pokazano pierwszą klatkę.",
    "USZKODZONY": "Nie udało się zdekodować obrazka.",
    "LIMIT_LICZBY": "Ponad 20 obrazków w wiadomości — pominięty.",
    "PRZESKALOWANY": "Szerszy niż 1600 px — pokazano pomniejszony.",
}
_Z_MIME = {"image/png": "PNG", "image/jpeg": "JPEG", "image/jpg": "JPEG", "image/pjpeg": "JPEG",
           "image/gif": "GIF", "image/bmp": "BMP", "image/x-ms-bmp": "BMP", "image/tiff": "TIFF",
           "image/webp": "WEBP", "image/svg+xml": "SVG", "image/x-icon": "ICO",
           "image/vnd.microsoft.icon": "ICO", "image/jp2": "JPEG2000", "image/avif": "AVIF/HEIC",
           "image/heic": "AVIF/HEIC", "application/postscript": "EPS"}
_Z_ROZSZERZENIA = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "jpe": "JPEG", "gif": "GIF", "bmp": "BMP",
                   "tif": "TIFF", "tiff": "TIFF", "webp": "WEBP", "svg": "SVG", "eps": "EPS", "ps": "EPS",
                   "ico": "ICO", "psd": "PSD", "jp2": "JPEG2000", "j2k": "JPEG2000", "avif": "AVIF/HEIC",
                   "heic": "AVIF/HEIC", "heif": "AVIF/HEIC"}


@dataclass
class WynikObrazka:
    wpis: dict
    png: bytes | None


def wykryj_format(dane: bytes) -> str:
    """Wyłącznie po sygnaturze bajtów — żaden dekoder nie jest uruchamiany."""
    if dane.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if dane.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if dane[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if dane.startswith(b"BM") and len(dane) > 26:
        return "BMP"
    if dane[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    if dane.startswith(b"RIFF") and dane[8:12] == b"WEBP":
        return "WEBP"
    if dane.startswith(b"\x00\x00\x01\x00"):
        return "ICO"
    if dane.startswith(b"8BPS"):
        return "PSD"
    if dane.startswith(b"\x00\x00\x00\x0cjP  \r\n\x87\n") or dane.startswith(b"\xff\x4f\xff\x51"):
        return "JPEG2000"
    if dane[4:8] == b"ftyp" and dane[8:12] in (b"avif", b"avis", b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
        return "AVIF/HEIC"
    if dane.startswith(b"%!PS") or dane.startswith(b"\xc5\xd0\xd3\xc6"):
        return "EPS"
    poczatek = dane[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if poczatek.startswith(b"<svg") or (poczatek.startswith(b"<?xml") and b"<svg" in poczatek):
        return "SVG"
    return "NIEZNANY"


def czy_obrazek(z: Zalacznik) -> bool:
    return z.typ_mime.startswith("image/") or bool(z.content_id) or wykryj_format(z.dane) != "NIEZNANY"


def _uwaga(kod: str, **kw) -> dict:
    return {"kod": kod, "opis": OPISY[kod].format(**kw)}


def _deklarowane(z: Zalacznik) -> list[str]:
    formaty = []
    if z.typ_mime in _Z_MIME:
        formaty.append(_Z_MIME[z.typ_mime])
    rozszerzenie = z.nazwa.rsplit(".", 1)[-1].lower() if "." in z.nazwa else ""
    if rozszerzenie in _Z_ROZSZERZENIA:
        formaty.append(_Z_ROZSZERZENIA[rozszerzenie])
    return formaty


def _pominiety(wpis: dict, powod: str) -> WynikObrazka:
    wpis["status"] = "pominiety"
    wpis["powod"] = powod
    return WynikObrazka(wpis, None)


def _przetworz(z: Zalacznik, numer: int) -> WynikObrazka:
    fmt = wykryj_format(z.dane)
    wpis = {"nazwa": z.nazwa, "sha256": z.sha256, "rozmiar": z.rozmiar, "content_id": z.content_id,
            "mime_zadeklarowany": z.typ_mime, "format_wykryty": fmt, "szerokosc": None, "wysokosc": None,
            "klatki": None, "status": "przekodowany", "uwagi": []}
    uwagi = wpis["uwagi"]
    niezgodne = [d for d in _deklarowane(z) if d != fmt]
    if niezgodne:
        uwagi.append(_uwaga("FORMAT_NIEZGODNY", format=fmt, deklaracja=niezgodne[0]))
    if z.rozmiar > MAKS_PLIK:
        uwagi.append(_uwaga("ZA_DUZY_PLIK"))
        return _pominiety(wpis, "za duży plik")
    if fmt not in DOZWOLONE:
        uwagi.append(_uwaga("FORMAT_NIEOBSLUGIWANY", format=fmt))
        return _pominiety(wpis, f"format {fmt}")
    if numer >= MAKS_LICZBA:
        uwagi.append(_uwaga("LIMIT_LICZBY"))
        return _pominiety(wpis, "limit liczby")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", Image.DecompressionBombWarning)  # własny limit poniżej
            obraz = Image.open(io.BytesIO(z.dane), formats=DOZWOLONE)
        szer, wys = obraz.size
        wpis.update(szerokosc=szer, wysokosc=wys, klatki=getattr(obraz, "n_frames", 1))
    except Image.DecompressionBombError:
        uwagi.append(_uwaga("ZA_DUZO_PIKSELI"))
        return _pominiety(wpis, "za duży obraz")
    except Exception:
        uwagi.append(_uwaga("USZKODZONY"))
        return _pominiety(wpis, "uszkodzony")
    with obraz:
        if szer * wys > MAKS_PIKSELI:
            uwagi.append(_uwaga("ZA_DUZO_PIKSELI"))
            return _pominiety(wpis, "za duży obraz")
        if max(szer, wys) > MAKS_BOK or max(szer, wys) > MAKS_PROPORCJE * max(1, min(szer, wys)):
            uwagi.append(_uwaga("NIETYPOWE_WYMIARY"))
        if wpis["klatki"] > 1:
            uwagi.append(_uwaga("ANIMACJA"))
        try:
            obraz.seek(0)
            klatka = obraz.convert("RGBA")
            if szer > SZEROKOSC_WYJSCIA:
                klatka = klatka.resize((SZEROKOSC_WYJSCIA, max(1, round(wys * SZEROKOSC_WYJSCIA / szer))))
                uwagi.append(_uwaga("PRZESKALOWANY"))
            bufor = io.BytesIO()
            klatka.save(bufor, "PNG")
        except Exception:
            uwagi.append(_uwaga("USZKODZONY"))
            return _pominiety(wpis, "uszkodzony")
    png = bufor.getvalue()
    if len(png) > MAKS_PNG:
        uwagi.append(_uwaga("ZA_DUZY_PLIK"))
        return _pominiety(wpis, "za duży plik")
    return WynikObrazka(wpis, png)


def _wiadomosci(w: Wiadomosc) -> Iterator[Wiadomosc]:
    yield w

    def zalaczniki(lista):
        for z in lista:
            yield z
            yield from zalaczniki(z.dzieci)

    for z in zalaczniki(w.zalaczniki):
        if z.wiadomosc is not None:
            yield from _wiadomosci(z.wiadomosc)


def przetworz_obrazki(w: Wiadomosc) -> dict[str, list[WynikObrazka]]:
    """Obrazki (załączniki i osadzone) każdej wiadomości, także zagnieżdżonych; klucz = Wiadomosc.id."""
    wynik = {}
    for x in _wiadomosci(w):
        obrazki = [z for z in x.zalaczniki if czy_obrazek(z)]
        wynik[x.id] = [_przetworz(z, i) for i, z in enumerate(obrazki)]
    return wynik
