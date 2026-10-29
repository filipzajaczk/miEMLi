import logging

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from analizy.models import IOC, Analiza, Zdarzenie
from analizy.uslugi import utworz_lub_otworz
from analizy.wyszukiwanie import rozpoznaj, szukaj, uzbroj

pytestmark = pytest.mark.django_db


@pytest.fixture
def phish(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "phish.eml", analityk)[0]


@pytest.fixture
def zip_(probka, analityk):
    return utworz_lub_otworz(probka("zip_exe"), "faktura.eml", analityk)[0]


def artefakt(a, typ, wartosc, **kw):
    return IOC.objects.create(analiza=a, numer=1000 + IOC.objects.count(), typ=typ, wartosc=wartosc,
                              zrodlo="tresc", **kw)


def pk(wynik):
    return [a.pk for a in wynik.analizy]


@pytest.mark.parametrize("wejscie,wyjscie", [
    ("hxxps://evil[.]com/x", "https://evil.com/x"), ("1.2.3[.]4", "1.2.3.4"), ("jan[@]evil(.)com", "jan@evil.com"),
    ("evil[dot]com", "evil.com"), ("HXXP://a[.]b", "http://a.b"), ("  x  ", "x"), ("a[:]b", "a:b"),
])
def test_uzbroj(wejscie, wyjscie):
    assert uzbroj(wejscie) == wyjscie


def test_uzbroj_dlugosc():
    assert len(uzbroj("x" * 100000)) == 2048


@pytest.mark.parametrize("wejscie,rodzaj,wartosc", [
    ("A" * 64, "hash", "a" * 64), ("b" * 32, "hash", "b" * 32), ("c" * 40, "hash", "c" * 40),
    ("185.243.115.20", "ip", "185.243.115.20"), ("2001:DB8::1", "ip", "2001:db8::1"),
    ("Jan@Evil.COM", "email", "jan@evil.com"), ("https://evil.com/x", "url", "https://evil.com/x"),
    ("Login.Evil.com", "domena", "login.evil.com"), ("bücher.example", "domena", "xn--bcher-kva.example"),
    ("com", "tekst", "com"), ("faktura za maj", "tekst", "faktura za maj"), ("ab", "za_krotki", "ab"),
])
def test_rozpoznaj(wejscie, rodzaj, wartosc):
    assert rozpoznaj(wejscie) == (rodzaj, wartosc)


def test_hash_artefaktu_i_md5(zip_, phish):
    plik = zip_.ioc.filter(typ="plik").first()
    assert pk(szukaj(plik.wartosc)) == [zip_.pk]
    w = szukaj(plik.hashe["md5"].upper())
    assert pk(w) == [zip_.pk] and w.dopasowania[zip_.pk].startswith("plik:")


def test_hash_calego_pliku(zip_):
    w = szukaj(zip_.sha256)
    assert pk(w) == [zip_.pk] and w.dopasowania[zip_.pk] == "plik .eml/.msg"


def test_ip_email_url(phish, zip_):
    assert pk(szukaj("185.243.115[.]20")) == [phish.pk]
    assert pk(szukaj("KSIEGOWOSC@pko-platnosci.example")) == [phish.pk]
    assert pk(szukaj("hxxps://pko-platnosci[.]example/login")) == [phish.pk]


def test_domena_z_subdomena(phish, zip_):
    artefakt(zip_, "domena", "login.pko-platnosci.example")
    w = szukaj("pko-platnosci.example")
    assert set(pk(w)) == {phish.pk, zip_.pk}
    assert w.dopasowania[zip_.pk] == "domena: login[.]pko-platnosci[.]example"


def test_bez_falszywej_subdomeny(phish, zip_):
    artefakt(zip_, "domena", "notevil.com")
    artefakt(phish, "domena", "evil.com")
    assert pk(szukaj("evil.com")) == [phish.pk]


def test_tekst(phish, zip_):
    assert pk(szukaj("zaległa")) == [phish.pk] and szukaj("zaległa").dopasowania[phish.pk] == "temat"
    assert szukaj("FAKTURA.eml").dopasowania[zip_.pk] == "nazwa pliku"
    zip_.notatka = "kampania Emotet listopad"
    zip_.save()
    assert szukaj("emotet").dopasowania[zip_.pk] == "komentarz"


def test_za_krotki(phish):
    w = szukaj("ab")
    assert w.analizy == [] and w.komunikat == "Wpisz co najmniej 3 znaki."


def test_limit_200(phish, analityk):
    wynik = phish.wynik
    Analiza.objects.bulk_create(Analiza(sha256=f"{n:064x}", nazwa_pliku="x.eml", wynik=wynik, utworzyl=analityk,
                                        temat_wiadomosci="masowa kampania") for n in range(201))
    w = szukaj("masowa")
    assert len(w.analizy) == 200 and w.obcieto


def test_wymaga_logowania(client):
    r = client.get(reverse("szukaj") + "?q=evil.com")
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_bez_wyniku_w_sql(zalogowany, phish):
    with CaptureQueriesContext(connection) as zapytania:
        t = zalogowany.get(reverse("szukaj") + "?q=pko-platnosci.example").content.decode()
    assert "phish.eml" in t and "Dopasowanie" in t
    assert not any('"wynik"' in q["sql"] for q in zapytania.captured_queries if "analizy_analiza" in q["sql"])


def test_wrogie_q(zalogowany, phish, caplog):
    zdarzenia = Zdarzenie.objects.count()
    with caplog.at_level(logging.DEBUG):
        t = zalogowany.get(reverse("szukaj"), {"q": "<script>alert(1)</script>"}).content.decode()
        r = zalogowany.get(reverse("szukaj"), {"q": "a\x00b" + "x" * 100000})
    assert "<script>alert(1)" not in t and "&lt;script&gt;" in t
    assert r.status_code == 200
    assert "alert(1)" not in caplog.text and Zdarzenie.objects.count() == zdarzenia


def test_pole_w_pasku(zalogowany):
    t = zalogowany.get(reverse("analizy:lista")).content.decode()
    assert 'action="/szukaj/"' in t and 'name="q"' in t


@pytest.mark.parametrize("url,host", [
    ("http://paypal.com@evil.com/login", "evil.com"),
    ("https://evil.com/l?u=victim@corp.pl", "evil.com"),
    ("https://u:p@evil.com:8443/", "evil.com"),
])
def test_url_z_malpa(phish, url, host):
    assert rozpoznaj(url) == ("url", url)
    artefakt(phish, "url", url)
    artefakt(phish, "domena", host)
    w = szukaj(url)
    assert pk(w) == [phish.pk]


def test_url_ipv6_host(phish):
    artefakt(phish, "ip", "2001:db8::1")
    assert rozpoznaj("http://[2001:db8::1]/x")[0] == "url"


def test_domena_idn(phish, zip_):
    artefakt(phish, "domena", "päypal.com")
    artefakt(zip_, "domena", "login.päypal.com")
    assert set(pk(szukaj("päypal.com"))) == {phish.pk, zip_.pk}
    assert set(pk(szukaj("xn--pypal-gra.com"))) == {phish.pk, zip_.pk}
