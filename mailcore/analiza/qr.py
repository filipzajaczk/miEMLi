import io

import zxingcpp
from PIL import Image


def odczytaj_qr(dane: bytes) -> list[str]:
    try:
        with Image.open(io.BytesIO(dane)) as obraz:
            obraz.load()
            return [k.text for k in zxingcpp.read_barcodes(obraz) if k.text]
    except Exception:
        return []
