import json

from mailcore.analiza import analizuj
from mailcore.parsuj import parsuj
from mailcore.serializacja import do_json


def klucze(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from klucze(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from klucze(v)


def test_do_json_bez_bajtow(zbuduj_mail):
    wewn = zbuduj_mail(temat="W", zalaczniki=[("a.bin", "application/octet-stream", b"SEKRET")])
    w = parsuj(zbuduj_mail(tekst="https://evil.com", zagniezdzone=[wewn],
                           naglowki=[("Received", "from a (a [1.1.1.1]) by b; Tue, 24 Oct 2026 09:14:00 +0200")]), "a.eml")
    j = do_json(w, analizuj(w))
    tekst = json.dumps(j)
    assert "dane" not in set(klucze(j))
    assert {"wiadomosc", "analiza", "ioc"} <= set(j)
    assert j["wiadomosc"]["zalaczniki"][0]["wiadomosc"]["id"] == "0.1"
    assert j["analiza"]["0"]["received"][0]["ip"] == "1.1.1.1"
    assert "U0VLUkVU" not in tekst  # base64("SEKRET")
