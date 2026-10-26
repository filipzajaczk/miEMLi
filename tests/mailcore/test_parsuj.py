import pytest

from mailcore.model import Limity, NieobslugiwanyPlik, PlikZaDuzy
from mailcore.parsuj import parsuj


def test_za_duzy():
    with pytest.raises(PlikZaDuzy):
        parsuj(b"x" * 11, "a.eml", Limity(max_rozmiar=10))


def test_nie_mail():
    with pytest.raises(NieobslugiwanyPlik):
        parsuj(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "a.eml")


def test_pusty_plik():
    with pytest.raises(NieobslugiwanyPlik):
        parsuj(b"", "a.eml")


def test_zagniezdzony_eml(zbuduj_mail):
    wewn = zbuduj_mail(temat="Wewnętrzny")
    dane = zbuduj_mail(temat="Zewnętrzny", zagniezdzone=[wewn])
    w = parsuj(dane, "a.eml")
    z = w.zalaczniki[0]
    assert z.wiadomosc is not None
    assert z.wiadomosc.temat == "Wewnętrzny"
    assert z.wiadomosc.id == "0.1"


def test_limit_glebokosci(zbuduj_mail):
    dane = zbuduj_mail(temat="poziom 7")
    for i in range(6, -1, -1):
        dane = zbuduj_mail(temat=f"poziom {i}", zagniezdzone=[dane])
    w = parsuj(dane, "a.eml", Limity(max_glebokosc=5))
    ids = []
    biezaca = w
    while biezaca.zalaczniki and biezaca.zalaczniki[0].wiadomosc:
        biezaca = biezaca.zalaczniki[0].wiadomosc
        ids.append(biezaca.id)
    assert ids[-1] == "0.1.1.1.1.1"
    assert len(ids) == 5
    assert "LIMIT_GLEBOKOSC" in [o.kod for o in biezaca.ostrzezenia]
