import io

import segno

from mailcore.analiza.qr import odczytaj_qr


def png_qr(tresc: str) -> bytes:
    buf = io.BytesIO()
    segno.make(tresc, error="m").save(buf, kind="png", scale=6, border=4)
    return buf.getvalue()


def test_qr():
    assert odczytaj_qr(png_qr("https://evil.com/qr")) == ["https://evil.com/qr"]


def test_qr_nie_obraz():
    assert odczytaj_qr(b"nie obraz") == []


def test_qr_w_tiff_odrzucony():
    # Pillow rozpoznaje format po zawartości — dopuszczamy tylko PNG/JPEG/GIF/BMP (mniejsza powierzchnia ataku)
    from PIL import Image

    buf = io.BytesIO()
    Image.open(io.BytesIO(png_qr("https://evil.com/qr"))).save(buf, "TIFF")
    assert odczytaj_qr(buf.getvalue()) == []


def test_eps_odrzucony_bez_ghostscriptu(monkeypatch):
    import subprocess

    wywolania = []

    def zapisz(*a, **kw):
        wywolania.append(a)
        raise OSError("zablokowane w teście")

    monkeypatch.setattr(subprocess, "Popen", zapisz)
    monkeypatch.setattr(subprocess, "check_call", zapisz)
    eps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\nshowpage\n"
    assert odczytaj_qr(eps) == []
    assert wywolania == [], "Pillow próbował uruchomić Ghostscript"


def test_twardy_limit_pikseli():
    from PIL import Image

    import mailcore.analiza.qr  # noqa: F401 — import ustawia limit

    assert Image.MAX_IMAGE_PIXELS == 20_000_000
