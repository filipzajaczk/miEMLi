from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from analizy import zadania
from analizy.models import Wzbogacenie
from analizy.uslugi import utworz_lub_otworz
from integracje.wspolne import WynikDostawcy

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def klucze(settings):
    settings.GTI_API_KEY = "k"
    settings.CENSYS_API_TOKEN = "t"
    settings.CENSYS_ORG_ID = ""


@pytest.fixture
def kolejka(monkeypatch):
    wywolania = []
    monkeypatch.setattr(zadania, "_kolejkuj", lambda f, *a, **kw: wywolania.append((f, a, kw)))
    return wywolania


@pytest.fixture
def klienci(monkeypatch):
    stan = {"wynik": WynikDostawcy("gotowe", {"werdykt": "zlosliwy"}, {}, "L"), "wywolania": []}

    def sprawdz(dostawca):
        def f(typ, wartosc):
            stan["wywolania"].append((dostawca, typ, wartosc))
            return stan["wynik"]
        return f

    monkeypatch.setattr(zadania, "_klient", sprawdz)
    return stan


def pary(kolejka):
    return {(a[0], a[1], a[2]) for _, a, _ in kolejka}


def wpis(dostawca, typ, wartosc, **pola):
    return Wzbogacenie.objects.create(
        klucz=Wzbogacenie.klucz_dla(dostawca, typ, wartosc), dostawca=dostawca, typ=typ, wartosc=wartosc, **pola
    )


@pytest.fixture
def phishing(probka, analityk, kolejka, django_capture_on_commit_callbacks):
    with django_capture_on_commit_callbacks(execute=True):
        analiza, _ = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)
    return analiza


def test_nowa_analiza_kolejkuje(phishing, kolejka):
    p = pary(kolejka)
    assert ("gti", "url", "https://pko-platnosci.example/login") in p
    assert ("gti", "domena", "pko-platnosci.example") in p
    assert ("gti", "ip", "185.243.115.20") in p
    assert ("censys", "ip", "185.243.115.20") in p
    assert not any(t == "email" for _, t, _ in p)
    assert {d for d, t, _ in p if t != "ip"} == {"gti"}
    assert all(w.status == "oczekuje" and w.zlecono for w in Wzbogacenie.objects.all())


def test_swiezy_cache_bez_kolejki(phishing, kolejka):
    kolejka.clear()
    Wzbogacenie.objects.all().update(status="gotowe", sprawdzono=timezone.now() - timedelta(hours=1))
    assert zadania.zaplanuj(phishing) == 0 and kolejka == []


def test_stary_cache_kolejkuje(phishing, kolejka):
    kolejka.clear()
    Wzbogacenie.objects.all().update(status="gotowe", sprawdzono=timezone.now() - timedelta(hours=25))
    assert zadania.zaplanuj(phishing) == len(pary(kolejka)) > 0


def test_oczekuje_niedawno_bez_duplikatu(phishing, kolejka):
    kolejka.clear()
    Wzbogacenie.objects.all().update(zlecono=timezone.now() - timedelta(minutes=5))
    assert zadania.zaplanuj(phishing) == 0
    Wzbogacenie.objects.all().update(zlecono=timezone.now() - timedelta(minutes=11))
    assert zadania.zaplanuj(phishing) > 0


def test_wymus(phishing, kolejka):
    kolejka.clear()
    Wzbogacenie.objects.all().update(status="gotowe", sprawdzono=timezone.now())
    assert zadania.zaplanuj(phishing, wymus=True) == Wzbogacenie.objects.count()


def test_tylko_brakujace(phishing, kolejka):
    kolejka.clear()
    Wzbogacenie.objects.all().update(status="gotowe", sprawdzono=timezone.now() - timedelta(days=3))
    Wzbogacenie.objects.filter(dostawca="censys").delete()
    zadania.zaplanuj(phishing, tylko_brakujace=True)
    assert pary(kolejka) == {("censys", "ip", "185.243.115.20")}


def test_brak_klucza(probka, analityk, kolejka, settings, django_capture_on_commit_callbacks):
    settings.CENSYS_API_TOKEN = ""
    with django_capture_on_commit_callbacks(execute=True):
        utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)
    assert not any(d == "censys" for d, _, _ in pary(kolejka))


def test_wspolny_cache_miedzy_analizami(probka, analityk, kolejka, klienci, django_capture_on_commit_callbacks):
    with django_capture_on_commit_callbacks(execute=True):
        utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=1)
    for f, a, kw in list(kolejka):
        f(*a, **kw)
    kolejka.clear()
    with django_capture_on_commit_callbacks(execute=True):
        utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=2)
    assert ("gti", "domena", "evil.example") not in pary(kolejka)


def test_wzbogac_zapisuje(klienci):
    wpis("gti", "domena", "evil.example", status="oczekuje", zlecono=timezone.now())
    zadania.wzbogac("gti", "domena", "evil.example")
    w = Wzbogacenie.objects.get()
    assert (w.status, w.skrot, w.link) == ("gotowe", {"werdykt": "zlosliwy"}, "L")
    assert w.sprawdzono is not None


def test_wzbogac_bez_wpisu_tworzy(klienci):
    zadania.wzbogac("gti", "domena", "nowa.example")
    assert Wzbogacenie.objects.get().status == "gotowe"


def test_otwarcie_istniejacej_kolejkuje_tylko_brakujace(phishing, kolejka, zalogowany):
    kolejka.clear()
    Wzbogacenie.objects.all().update(status="gotowe", sprawdzono=timezone.now() - timedelta(days=3))
    Wzbogacenie.objects.filter(typ="url").delete()
    zalogowany.get(reverse("analizy:szczegoly", args=[phishing.pk]))
    assert pary(kolejka) == {
        ("gti", "url", "https://pko-platnosci.example/login"),
        ("gti", "url", "https://pko-platnosci.example/fv"),
    }
