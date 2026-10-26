import io

import zxingcpp
from PIL import Image

MAKS_PIKSELI = 20_000_000


def odczytaj_qr(dane: bytes) -> list[str]:
    try:
        with Image.open(io.BytesIO(dane)) as obraz:  # open() czyta tylko nagłówek
            szer, wys = obraz.size
            if szer * wys > MAKS_PIKSELI:
                return []
            obraz.load()
            return [k.text for k in zxingcpp.read_barcodes(obraz) if k.text]
    except Exception:
        return []
