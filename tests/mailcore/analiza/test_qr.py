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
