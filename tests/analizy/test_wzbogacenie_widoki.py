import time
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from analizy import zadania
from analizy.models import Wzbogacenie
from analizy.templatetags.miemli import wiek
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def srodowisko(settings, monkeypatch):
    settings.GTI_API_KEY = "k"
    settings.CENSYS_API_TOKEN = "t"
    wywolania = []
    monkeypatch.setattr(zadania, "_kolejkuj", lambda f, *a, **kw: wywolania.append(a))
    return wywolania


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


def wpis(dostawca, typ, wartosc, **pola):
    pola.setdefault("status", "gotowe")
    pola.setdefault("sprawdzono", timezone.now())
    return Wzbogacenie.objects.update_or_create(
        klucz=Wzbogacenie.klucz_dla(dostawca, typ, wartosc),
        defaults={"dostawca": dostawca, "typ": typ, "wartosc": wartosc, **pola},
    )[0]


def wszystkie_gotowe(analiza):
    for i in analiza.ioc.all():
        for d in zadania.DOSTAWCY:
            if i.typ in zadania.DOSTAWCY[d]:
                wpis(d, i.typ, i.wartosc)


def strona(klient, analiza, **params):
    from urllib.parse import urlencode
    url = reverse("analizy:szczegoly", args=[analiza.pk])
    return klient.get(url + ("?" + urlencode(params) if params else "")).content.decode()


def fragment(klient, analiza):
    return klient.get(reverse("analizy:wzbogacenie", args=[analiza.pk])).content.decode()


def test_kolumny(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert ">GTI<" in t and ">Censys<" in t and ">JOE<" in t


def test_komorka_gti_zlosliwy(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "url", "https://pko-platnosci.example/login",
         skrot={"werdykt": "zlosliwy", "ocena": 80, "wykrycia": [12, 90]})
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert "złośliwy · 80 · 12/90" in t
    assert 'class="b bad"' in t


def test_nowa_domena(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "domena", "pko-platnosci.example",
         skrot={"werdykt": "niewykryty", "utworzono": int(time.time()) - 3 * 86400})
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert '<span class="b warn">3 dni</span>' in t


def test_censys_uslugi(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    uslugi = [[p, "HTTP", "tcp"] for p in (21, 22, 25, 53, 80, 443, 8080)]
    wpis("censys", "ip", "185.243.115.20", skrot={"uslugi": uslugi, "asn": 15169})
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert "80 HTTP" in t and "443 HTTP" not in t and "+2" in t and "AS15169" in t


def test_censys_brak_uslug(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("censys", "ip", "185.243.115.20", skrot={"uslugi": [], "asn": None})
    assert "brak otwartych usług" in strona(zalogowany, analiza, sekcja="ioc")


def test_odpytywanie_gdy_oczekuje(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "ip", "185.243.115.20", status="oczekuje", zlecono=timezone.now(), sprawdzono=None)
    t = strona(zalogowany, analiza)
    assert 'hx-trigger="every 2s"' in t
    assert "…" in strona(zalogowany, analiza, sekcja="ioc")


def test_brak_odpytywania_gdy_gotowe(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    assert "every 2s" not in strona(zalogowany, analiza)
    assert "every 2s" not in fragment(zalogowany, analiza)


def test_wiszacy_wpis_jako_blad(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "ip", "185.243.115.20", status="oczekuje",
         zlecono=timezone.now() - timedelta(minutes=11), sprawdzono=None)
    t = fragment(zalogowany, analiza)
    assert "Brak odpowiedzi workera." in t
    assert "every 2s" not in t


def test_klucz_usuniety_wynik_widoczny(zalogowany, analiza, settings):
    wpis("gti", "url", "https://pko-platnosci.example/login", skrot={"werdykt": "zlosliwy"})
    settings.GTI_API_KEY = ""
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert "złośliwy" in t
    assert "brak klucza w .env" in t


def test_brak_danych_i_limit(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "url", "https://pko-platnosci.example/login", status="brak_danych")
    wpis("gti", "url", "https://pko-platnosci.example/fv", status="limit", blad="Przekroczono limit zapytań API.")
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert "brak danych" in t and "limit API" in t


def test_fragment_oob(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    t = fragment(zalogowany, analiza)
    assert 'id="panel-ioc"' in t and 'id="tabela-ioc-cialo"' in t and "hx-swap-oob" in t
    assert "<html" not in t


def test_fragment_wymaga_logowania(client, analiza):
    assert client.get(reverse("analizy:wzbogacenie", args=[analiza.pk])).status_code == 302


def test_wiek():
    teraz = time.time()
    dzien = 86400
    assert wiek(teraz - 1 * dzien - 60) == "1 dzień"
    assert wiek(teraz - 3 * dzien - 60) == "3 dni"
    assert wiek(teraz - 60 * dzien - 60) == "2 mies."
    assert wiek(teraz - 3 * 365 * dzien - 60) == "3 lata"
    assert wiek(teraz - 27 * 365 * dzien - 60) == "27 lat"
    assert wiek(teraz - 22 * 365 * dzien - 60) == "22 lata"
    assert wiek(teraz - 12 * 365 * dzien - 60) == "12 lat"
    assert wiek(teraz - 1 * 365 * dzien - 60) == "1 rok"
    assert wiek(None) == ""


def ioc_typu(analiza, typ):
    return analiza.ioc.filter(typ=typ).first()


def test_szczegoly_gti_i_censys(zalogowany, analiza):
    ip = ioc_typu(analiza, "ip")
    wpis("gti", "ip", ip.wartosc, link=f"https://www.virustotal.com/gui/ip-address/{ip.wartosc}",
         skrot={"werdykt": "nieszkodliwy", "kraj": "US", "asn": 15169, "wlasciciel": "Google LLC", "tagi": []})
    wpis("censys", "ip", ip.wartosc, link=f"https://platform.censys.io/hosts/{ip.wartosc}",
         skrot={"uslugi": [[53, "DNS", "udp"]], "asn": 15169, "as_nazwa": "GOOGLE", "bgp": "8.8.8.0/24",
                "kraj": "US", "miasto": "Mountain View", "dns": ["dns.google"]})
    t = zalogowany.get(reverse("analizy:szczegoly_ioc", args=[analiza.pk, ip.pk])).content.decode()
    assert "Google LLC" in t and "8.8.8.0/24" in t and "dns[.]google" in t
    assert 'href="https://platform.censys.io/hosts/' in t
    assert 'href="https://www.virustotal.com/gui/ip-address/' in t
    assert "Sprawdzono:" in t


def test_szczegoly_cudzy_ioc_404(zalogowany, analiza, probka, analityk):
    inna = utworz_lub_otworz(probka("zip_exe"), "z.eml", analityk)[0]
    r = zalogowany.get(reverse("analizy:szczegoly_ioc", args=[analiza.pk, inna.ioc.first().pk]))
    assert r.status_code == 404


def test_wrogie_dane_api(zalogowany, analiza):
    url = ioc_typu(analiza, "url")
    wpis("gti", "url", url.wartosc,
         skrot={"werdykt": "zlosliwy", "nazwy": ["<script>alert(1)</script>"], "tagi": ["<b>x</b>"]},
         surowe={"data": {"attributes": {"last_final_url": "https://evil.example/x"}}})
    t = zalogowany.get(reverse("analizy:szczegoly_ioc", args=[analiza.pk, url.pk])).content.decode()
    assert "&lt;b&gt;x&lt;/b&gt;" in t
    assert "<script>alert" not in t and "<b>x</b>" not in t
    assert "https://evil.example" not in t


def test_odswiez_post(zalogowany, analiza, srodowisko):
    wszystkie_gotowe(analiza)
    srodowisko.clear()
    r = zalogowany.post(reverse("analizy:odswiez", args=[analiza.pk]))
    assert r.status_code == 302 and r.url == reverse("analizy:szczegoly", args=[analiza.pk])
    assert analiza.zdarzenia.filter(typ="odswiezenie").exists()
    assert len(srodowisko) == Wzbogacenie.objects.count()


def test_odswiez_get_405(zalogowany, analiza):
    assert zalogowany.get(reverse("analizy:odswiez", args=[analiza.pk])).status_code == 405


def test_odswiez_wymaga_logowania(client, analiza, srodowisko):
    r = client.post(reverse("analizy:odswiez", args=[analiza.pk]))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))
    assert srodowisko == []


def test_przycisk_odswiez(zalogowany, analiza):
    t = strona(zalogowany, analiza)
    assert reverse("analizy:odswiez", args=[analiza.pk]) in t and "Odśwież wzbogacenie" in t


def test_link_joe(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    t = strona(zalogowany, analiza, sekcja="ioc")
    assert 'href="https://jbxcloud.joesecurity.org/" target="_blank" rel="noopener noreferrer"' in t
    assert t.count("jbxcloud.joesecurity.org") == analiza.ioc.filter(typ__in=["plik", "url"]).count()


def test_kropka_w_panelu(zalogowany, analiza):
    wszystkie_gotowe(analiza)
    wpis("gti", "url", "https://pko-platnosci.example/login", skrot={"werdykt": "zlosliwy"})
    assert 'class="kropka bad"' in strona(zalogowany, analiza)
