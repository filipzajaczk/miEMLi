import importlib

import pytest
from django.apps import apps
from django.urls import reverse

from analizy import prezentacja
from analizy.models import IOC
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db
DOMENA = "pko-platnosci.example"


@pytest.fixture
def trzy(probka, analityk):
    pierwsza = utworz_lub_otworz(probka("phishing_klasyczny"), "a.eml", analityk)[0]
    inne = [utworz_lub_otworz(probka(n), f"{n}.eml", analityk)[0] for n in ("zip_exe", "safelinks")]
    for a in inne:
        IOC.objects.create(analiza=a, numer=999, typ="domena", wartosc=DOMENA, zrodlo="tresc",
                           skrot=IOC.skrot_dla("domena", DOMENA))
    return pierwsza, inne


def domena(a):
    return a.ioc.get(typ="domena", wartosc=DOMENA)


def test_skrot_przy_tworzeniu(trzy):
    i = domena(trzy[0])
    assert i.skrot == IOC.skrot_dla("domena", DOMENA) and len(i.skrot) == 64


def test_odznaka(zalogowany, trzy):
    a = trzy[0]
    assert prezentacja.inne_analizy(a)[domena(a).pk] == 2
    t = zalogowany.get(reverse("analizy:szczegoly", args=[a.pk]) + "?sekcja=ioc").content.decode()
    assert "w 2 innych analizach" in t and f'href="/szukaj/?q={DOMENA}"' in t


def test_forma_1(zalogowany, trzy):
    a = trzy[1][0]
    assert prezentacja.inne_analizy(a)[domena(a).pk] == 2
    IOC.objects.filter(analiza=trzy[1][1], wartosc=DOMENA).delete()
    t = zalogowany.get(reverse("analizy:szczegoly", args=[a.pk])).content.decode()
    assert "w 1 innej analizie" in t


def test_bez_biezacej(trzy):
    a = trzy[0]
    unikalne = a.ioc.exclude(wartosc=DOMENA).exclude(typ="domena").first()
    IOC.objects.create(analiza=a, numer=998, typ=unikalne.typ, wartosc=unikalne.wartosc, zrodlo="tresc",
                       skrot=unikalne.skrot)  # duplikat w tej samej analizie się nie liczy
    assert unikalne.pk not in prezentacja.inne_analizy(a)


def test_stala_liczba_zapytan(trzy, django_assert_max_num_queries):
    a = trzy[0]
    with django_assert_max_num_queries(2):
        prezentacja.inne_analizy(a)
    IOC.objects.bulk_create(IOC(analiza=a, numer=2000 + n, typ="domena", wartosc=f"d{n}.example", zrodlo="tresc",
                                skrot=IOC.skrot_dla("domena", f"d{n}.example")) for n in range(200))
    with django_assert_max_num_queries(2):
        prezentacja.inne_analizy(a)


def test_migracja_skrotu(trzy):
    IOC.objects.update(skrot="")
    importlib.import_module("analizy.migrations.0012_ioc_skrot").uzupelnij_skrot(apps, None)
    assert all(i.skrot == IOC.skrot_dla(i.typ, i.wartosc) for i in IOC.objects.all())
