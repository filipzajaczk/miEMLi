import io

import pytest
from PIL import Image

from mailcore.model import Wiadomosc, zalacznik_z_danych
from piaskownica.obrazki import przetworz_obrazki, wykryj_format


def obraz(fmt: str, w: int = 100, h: int = 50, **kw) -> bytes:
    buf = io.BytesIO()
    tryb = "RGB" if fmt not in ("GIF",) else "P"
    Image.new(tryb, (w, h), 0).save(buf, fmt, **kw)
    return buf.getvalue()


def gif_animowany(klatki: int = 3) -> bytes:
    buf = io.BytesIO()
    ramki = [Image.new("RGB", (40, 40), (60 * i, 0, 0)) for i in range(klatki)]
    ramki[0].save(buf, "GIF", save_all=True, append_images=ramki[1:])
    return buf.getvalue()


def wiadomosc(*zalaczniki, id="0") -> Wiadomosc:
    return Wiadomosc(id, [], "t", None, [], None, None, None, list(zalaczniki), [])


def zal(nazwa, mime, dane, cid=None):
    return zalacznik_z_danych(nazwa, mime, dane, content_id=cid, inline=bool(cid))


def wpis(w, i=0):
    return przetworz_obrazki(w)["0"][i]


def kody(wynik):
    return {u["kod"] for u in wynik.wpis["uwagi"]}


@pytest.mark.parametrize("dane,oczekiwany", [
    (obraz("PNG"), "PNG"), (obraz("JPEG"), "JPEG"), (obraz("GIF"), "GIF"), (obraz("BMP"), "BMP"),
    (obraz("TIFF"), "TIFF"), (obraz("WEBP"), "WEBP"), (obraz("ICO", 32, 32), "ICO"),
    (obraz("JPEG2000"), "JPEG2000"),
    (b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>', "SVG"),
    (b"  <svg></svg>", "SVG"), (b"%!PS-Adobe-3.0 EPSF-3.0\n", "EPS"), (b"8BPS\x00\x01", "PSD"),
    (b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00", "AVIF/HEIC"),
    (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00", "AVIF/HEIC"), (b"abc", "NIEZNANY"),
])
def test_wykryj_format(dane, oczekiwany):
    assert wykryj_format(dane) == oczekiwany


def test_bez_dekodera_dla_nieobslugiwanych(monkeypatch):
    tiff = obraz("TIFF")

    def zakaz(*a, **kw):
        raise AssertionError("dekoder uruchomiony dla nieobsługiwanego formatu")

    monkeypatch.setattr(Image, "open", zakaz)
    w = wpis(wiadomosc(zal("a.tif", "image/tiff", tiff)))
    assert w.wpis["status"] == "pominiety" and w.png is None
    assert "FORMAT_NIEOBSLUGIWANY" in kody(w)


def test_przekodowany_png_inny_niz_oryginal():
    dane = obraz("PNG")
    w = wpis(wiadomosc(zal("a.png", "image/png", dane, "c1")))
    assert w.wpis["status"] == "przekodowany" and w.png.startswith(b"\x89PNG") and w.png != dane
    assert (w.wpis["szerokosc"], w.wpis["wysokosc"], w.wpis["format_wykryty"]) == (100, 50, "PNG")
    assert w.wpis["content_id"] == "c1" and w.wpis["uwagi"] == []


def test_format_niezgodny():
    w = wpis(wiadomosc(zal("logo.png", "image/png", obraz("TIFF"))))
    assert {"FORMAT_NIEZGODNY", "FORMAT_NIEOBSLUGIWANY"} <= kody(w)
    w2 = wpis(wiadomosc(zal("a.png", "image/png", obraz("JPEG"))))
    assert "FORMAT_NIEZGODNY" in kody(w2) and w2.wpis["status"] == "przekodowany"


def test_jpg_zgodny_z_jpeg():
    assert kody(wpis(wiadomosc(zal("a.jpg", "image/jpeg", obraz("JPEG"))))) == set()


def test_animacja():
    w = wpis(wiadomosc(zal("a.gif", "image/gif", gif_animowany(3))))
    assert w.wpis["klatki"] == 3 and "ANIMACJA" in kody(w) and w.wpis["status"] == "przekodowany"


def test_za_duzo_pikseli():
    w = wpis(wiadomosc(zal("a.png", "image/png", obraz("PNG", 6000, 4000))))
    assert "ZA_DUZO_PIKSELI" in kody(w) and w.wpis["status"] == "pominiety"


def test_nietypowe_wymiary_i_przeskalowanie():
    w = wpis(wiadomosc(zal("a.png", "image/png", obraz("PNG", 20000, 10))))
    assert {"NIETYPOWE_WYMIARY", "PRZESKALOWANY"} <= kody(w)
    assert Image.open(io.BytesIO(w.png)).size[0] == 1600


def test_przeskalowany():
    w = wpis(wiadomosc(zal("a.png", "image/png", obraz("PNG", 3000, 100))))
    assert kody(w) == {"PRZESKALOWANY"} and Image.open(io.BytesIO(w.png)).size[0] == 1600


def test_uszkodzony():
    w = wpis(wiadomosc(zal("a.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30)))
    assert "USZKODZONY" in kody(w) and w.wpis["status"] == "pominiety"


def test_za_duzy_plik(monkeypatch):
    def zakaz(*a, **kw):
        raise AssertionError("dekodowanie zbyt dużego pliku")

    dane = obraz("BMP", 2000, 1800)
    assert len(dane) > 10 * 1024 * 1024
    monkeypatch.setattr(Image, "open", zakaz)
    w = wpis(wiadomosc(zal("a.bmp", "image/bmp", dane)))
    assert "ZA_DUZY_PLIK" in kody(w) and w.wpis["status"] == "pominiety"


def test_limit_liczby():
    w = wiadomosc(*[zal(f"{i}.png", "image/png", obraz("PNG", 10 + i, 10)) for i in range(25)])
    wyniki = przetworz_obrazki(w)["0"]
    assert [x.wpis["status"] for x in wyniki].count("przekodowany") == 20
    assert sum("LIMIT_LICZBY" in kody(x) for x in wyniki) == 5


def test_zalacznik_nie_obrazek_pominiety_w_raporcie():
    assert przetworz_obrazki(wiadomosc(zal("a.pdf", "application/pdf", b"%PDF-1.4")))["0"] == []


def test_ukryty_obrazek_bez_mime_wykryty():
    w = wpis(wiadomosc(zal("dane.bin", "application/octet-stream", obraz("PNG"))))
    assert w.wpis["format_wykryty"] == "PNG"


def test_zagniezdzona_wiadomosc():
    wewn = wiadomosc(zal("a.png", "image/png", obraz("PNG")), id="0.1")
    kontener = zal("wewn.eml", "message/rfc822", b"x")
    kontener.wiadomosc = wewn
    wynik = przetworz_obrazki(wiadomosc(kontener))
    assert wynik["0"] == [] and len(wynik["0.1"]) == 1
