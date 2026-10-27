import base64
from io import StringIO

import pytest
from django.core.management import call_command

from analizy.klucze_joe import (
    BladOdszyfrowania, nowa_para, odszyfruj_klucz, odszyfruj_plik, zaszyfruj_klucz, zaszyfruj_plik,
)

KLUCZ = "AbCdEf0123456789XyZ0123456789x7f3"


@pytest.fixture(autouse=True)
def para(settings):
    publiczny, prywatny = nowa_para()
    settings.JOE_KLUCZ_PUBLICZNY = publiczny
    settings.JOE_KLUCZ_PRYWATNY = prywatny
    return publiczny, prywatny


def test_round_trip_klucza():
    assert odszyfruj_klucz(7, zaszyfruj_klucz(7, KLUCZ)) == KLUCZ


def test_round_trip_pliku():
    dane = bytes(range(256)) * 1000
    assert odszyfruj_plik(3, zaszyfruj_plik(3, dane)) == dane


def test_inny_uzytkownik_odrzucony():
    with pytest.raises(BladOdszyfrowania):
        odszyfruj_klucz(8, zaszyfruj_klucz(7, KLUCZ))


def test_inne_zgloszenie_odrzucone():
    with pytest.raises(BladOdszyfrowania):
        odszyfruj_plik(4, zaszyfruj_plik(3, b"dane"))


def test_bez_klucza_prywatnego(settings):
    szyfrogram = zaszyfruj_klucz(7, KLUCZ)
    settings.JOE_KLUCZ_PRYWATNY = ""
    with pytest.raises(BladOdszyfrowania):
        odszyfruj_klucz(7, szyfrogram)


def test_wymiana_pary(settings):
    szyfrogram = zaszyfruj_klucz(7, KLUCZ)
    settings.JOE_KLUCZ_PUBLICZNY, settings.JOE_KLUCZ_PRYWATNY = nowa_para()
    with pytest.raises(BladOdszyfrowania):
        odszyfruj_klucz(7, szyfrogram)


def test_smieci_odrzucone():
    for zly in ("", "nie-base64!!", base64.b64encode(b"krotkie").decode()):
        with pytest.raises(BladOdszyfrowania):
            odszyfruj_klucz(7, zly)


def test_szyfrogram_nie_zawiera_jawnego():
    szyfrogram = zaszyfruj_klucz(7, KLUCZ)
    assert KLUCZ not in szyfrogram and KLUCZ.encode() not in base64.b64decode(szyfrogram)


def test_komenda_generuj(settings):
    out = StringIO()
    call_command("joe_generuj_klucze", stdout=out)
    linie = dict(l.split("=", 1) for l in out.getvalue().splitlines() if l.startswith("JOE_KLUCZ_"))
    settings.JOE_KLUCZ_PUBLICZNY = linie["JOE_KLUCZ_PUBLICZNY"]
    settings.JOE_KLUCZ_PRYWATNY = linie["JOE_KLUCZ_PRYWATNY"]
    assert odszyfruj_klucz(1, zaszyfruj_klucz(1, KLUCZ)) == KLUCZ
