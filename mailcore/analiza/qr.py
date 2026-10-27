import io
import warnings

import zxingcpp
from PIL import Image

MAKS_PIKSELI = 20_000_000
# Pillow wybiera dekoder po zawartości pliku, nie po MIME. Wrogi „obrazek” mógłby trafić do dekodera
# TIFF/JPEG2000/PSD (kod w C) albo EPS (uruchamia Ghostscript). Dopuszczamy tylko popularne formaty.
FORMATY = ("PNG", "JPEG", "GIF", "BMP")
Image.MAX_IMAGE_PIXELS = MAKS_PIKSELI  # większe obrazy: DecompressionBombError zamiast ostrzeżenia


def odczytaj_qr(dane: bytes) -> list[str]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)  # ostrzeżenie = odrzucenie
            return _odczytaj(dane)
    except Exception:
        return []


def _odczytaj(dane: bytes) -> list[str]:
    with Image.open(io.BytesIO(dane), formats=FORMATY) as obraz:  # open() czyta tylko nagłówek
        szer, wys = obraz.size
        if szer * wys > MAKS_PIKSELI:
            return []
        obraz.load()
        return [k.text for k in zxingcpp.read_barcodes(obraz) if k.text]
