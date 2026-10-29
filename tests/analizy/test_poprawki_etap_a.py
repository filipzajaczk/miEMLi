import importlib
import time
from types import SimpleNamespace

import pytest
from django.apps import apps
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from analizy.models import Analiza, ProfilAnalityka, ZgloszenieJoe
from analizy.templatetags.miemli import nowa_domena, rozbroj_tekst, wiek
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


def test_temat_przy_tworzeniu(probka, analityk):
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    assert a.temat_wiadomosci and a.temat_wiadomosci == a.wynik["wiadomosc"]["temat"]


def test_lista_bez_pola_wynik(zalogowany, probka, analityk):
    utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)
    utworz_lub_otworz(probka("zip_exe"), "z.eml", analityk)
    with CaptureQueriesContext(connection) as zapytania:
        t = zalogowany.get(reverse("analizy:lista")).content.decode()
    sql = [q["sql"] for q in zapytania.captured_queries if "analizy_analiza" in q["sql"]]
    assert sql and not any('"wynik"' in s for s in sql)
    assert Analiza.objects.get(nazwa_pliku="p.eml").temat_wiadomosci in t


def test_migracja_tematu(probka, analityk):
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    dlugi = utworz_lub_otworz(probka("zip_exe"), "z.eml", analityk)[0]
    Analiza.objects.filter(pk=a.pk).update(temat_wiadomosci="")
    Analiza.objects.filter(pk=dlugi.pk).update(temat_wiadomosci="", wynik={"wiadomosc": {"temat": "x" * 900}})
    migracja = importlib.import_module("analizy.migrations.0009_temat_wiadomosci")
    migracja.uzupelnij_temat(apps, None)
    a.refresh_from_db(); dlugi.refresh_from_db()
    assert a.temat_wiadomosci == a.wynik["wiadomosc"]["temat"]
    assert dlugi.temat_wiadomosci == "x" * 500


def test_wiek_przyszlosc():
    jutro = time.time() + 3 * 86400
    assert wiek(jutro) == "" and nowa_domena(jutro) is False
    assert wiek(time.time() - 5 * 86400) == "5 dni" and nowa_domena(time.time() - 5 * 86400)


@pytest.mark.parametrize("wejscie,oczekiwane", [
    ("faktura.pdf.exe", "faktura[.]pdf[.]exe"),
    ("https://evil.example/x", "hxxps://evil[.]example/x"),
    ("HTTP://Zly.Example", "hxxp://Zly[.]Example"),
    ("trojan.generic", "trojan[.]generic"),
    ("phishing", "phishing"),
    ("v1.2", "v1.2"),
])
def test_rozbroj_tekst(wejscie, oczekiwane):
    assert rozbroj_tekst(wejscie) == oczekiwane


def test_szczegoly_gti_rozbrojone():
    from django.template.loader import render_to_string

    html = render_to_string("analizy/_szczegoly_ioc.html", {
        "i": SimpleNamespace(typ="plik", rodzic=None),
        "wz": {"gti": {"status": "gotowe", "skrot": {"nazwy": ["zlo.exe"], "tagi": ["http://c2.example"]}}},
    })
    assert "zlo[.]exe" in html and "hxxp://c2[.]example" in html
    assert "zlo.exe" not in html


@pytest.fixture
def zgloszenie(probka, analityk, monkeypatch):
    from analizy import joe_zadania
    from analizy.models import profil_dla

    p = profil_dla(analityk)
    p.joe_klucz_stan = "dziala"
    p.save()
    monkeypatch.setattr(joe_zadania, "_klucz_analityka", lambda z: "A" * 40)
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    return ZgloszenieJoe.objects.create(analiza=a, uzytkownik=analityk, status="wyslane", id_zgloszenia="123")


def test_joe_odrzucony_klucz_zmienia_stan(zgloszenie, monkeypatch):
    from analizy import joe_zadania
    from integracje import joe

    monkeypatch.setattr(joe, "stan_zgloszenia", lambda *a: joe.WynikJoe(
        "odrzucony", blad="Klucz Joe odrzucony — sprawdź go w profilu.", klucz_odrzucony=True))
    joe_zadania.sprawdz_joe(zgloszenie.pk)
    assert ProfilAnalityka.objects.get(uzytkownik=zgloszenie.uzytkownik).joe_klucz_stan == "odrzucony"
    zgloszenie.refresh_from_db()
    assert zgloszenie.status == "blad"


def test_joe_odrzucony_plik_nie_zmienia_stanu(zgloszenie, monkeypatch):
    from analizy import joe_zadania
    from integracje import joe

    monkeypatch.setattr(joe, "stan_zgloszenia", lambda *a: joe.WynikJoe("odrzucony", blad="Joe nie przyjął pliku: x"))
    joe_zadania.sprawdz_joe(zgloszenie.pk)
    assert ProfilAnalityka.objects.get(uzytkownik=zgloszenie.uzytkownik).joe_klucz_stan == "dziala"
