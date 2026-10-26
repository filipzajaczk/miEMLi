import hashlib
from pathlib import Path

import pytest

from mailcore.parsuj import parsuj

PROBKI = Path(__file__).resolve().parent.parent / "samples"
PLIKI_MSG = sorted(PROBKI.glob("msg/*.msg")) + sorted(PROBKI.glob("private/**/*.msg"))

pytestmark = pytest.mark.skipif(not PLIKI_MSG, reason="brak próbek .msg")


@pytest.fixture(params=PLIKI_MSG, ids=lambda p: p.name)
def msg(request):
    return request.param.name, request.param.read_bytes()


def test_msg_parsuje_sie(msg):
    nazwa, dane = msg
    w = parsuj(dane, nazwa)
    assert w.id == "0"
    assert w.temat
    assert w.tekst or w.html


def test_msg_naglowki_transportowe(msg):
    nazwa, dane = msg
    w = parsuj(dane, nazwa)
    kody = [o.kod for o in w.ostrzezenia]
    if "MSG_BEZ_NAGLOWKOW" in kody:
        assert w.naglowek("Subject") and w.naglowek("From")
    else:
        assert w.naglowek("Received") is not None


def test_msg_zalaczniki_maja_hashe(msg):
    nazwa, dane = msg
    w = parsuj(dane, nazwa)
    for z in w.zalaczniki:
        assert z.sha256 == hashlib.sha256(z.dane).hexdigest()


def test_testowa_wiadomosc_z_outlooka():
    plik = PROBKI / "private" / "testowa_wiadomosc.msg"
    if not plik.exists():
        pytest.skip("brak prywatnej próbki")
    w = parsuj(plik.read_bytes(), plik.name)
    assert w.temat == "Testowa wiadomosc msg"
    assert "@" in (w.od or "")
