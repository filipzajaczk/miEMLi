import copy

import pytest
from django.urls import reverse

from analizy.models import Analiza, Wzbogacenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db
IP = "185.243.115.20"


@pytest.fixture
def analiza(probka, analityk, settings):
    settings.GTI_WLACZONE = settings.CENSYS_WLACZONE = True
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    assert IP in [h["ip"] for h in a.wynik["analiza"]["0"]["received"]]
    return a


def wpis(dostawca, status="gotowe", **skrot):
    Wzbogacenie.objects.update_or_create(
        klucz=Wzbogacenie.klucz_dla(dostawca, "ip", IP),
        defaults={"dostawca": dostawca, "typ": "ip", "wartosc": IP, "status": status, "skrot": skrot})


def sekcja(klient, a):
    return klient.get(reverse("analizy:szczegoly", args=[a.pk]) + "?sekcja=received").content.decode()


def test_kraj_z_gti(zalogowany, analiza):
    wpis("gti", kraj="RU", asn=12345, wlasciciel="Zly ISP")
    wpis("censys", kraj="DE", asn=1)
    t = sekcja(zalogowany, analiza)
    assert "RU" in t and "AS12345" in t and "Zly ISP" in t and "DE" not in t.split('id="os-czasu-cialo"')[1]


def test_kraj_z_censys_gdy_brak_gti(zalogowany, analiza):
    wpis("gti", status="brak_danych")
    wpis("censys", kraj="NL", asn=64512)
    t = sekcja(zalogowany, analiza)
    assert "NL" in t and "AS64512" in t


def test_oczekuje(zalogowany, analiza):
    wpis("gti", status="oczekuje")
    assert 'class="muted pulsuje">…<' in sekcja(zalogowany, analiza)


def test_ip_wewnetrzne(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    w["analiza"]["0"]["received"][0]["ip"] = "10.0.0.1"
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    assert "sieć wewnętrzna" in sekcja(zalogowany, analiza)


def test_uwagi_hopu(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    w["analiza"]["0"]["received"][0]["uwagi"] = [{"kod": "CZAS_WSTECZ", "opis": "Czas cofa się o 9 min"}]
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    assert '<span class="b bad">Czas cofa się o 9 min</span>' in sekcja(zalogowany, analiza)


def test_blok_klienta_i_arc(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    w["analiza"]["0"]["klient"] = {"x_mailer": "PHPMailer 6.0", "user_agent": None, "x_originating_ip": IP}
    w["analiza"]["0"]["arc"] = {"ogniwa": [{"i": 1, "serwer": "mx1.example", "spf": "pass", "dkim": "fail",
                                            "dmarc": None}], "kompletny": False, "cv": "none"}
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    t = sekcja(zalogowany, analiza)
    assert "PHPMailer 6.0" in t and "łańcuch niekompletny" in t
    assert ("Wyniki deklarowane przez serwery pośredniczące — podpisy ARC nie są weryfikowane "
            "kryptograficznie.") in t


def test_stara_analiza(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    for a in w["analiza"].values():
        a.pop("klient"), a.pop("arc")
        for h in a["received"]:
            h.pop("uwagi")
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    t = sekcja(zalogowany, analiza)
    assert "Klient i przekazanie" not in t and 'id="os-czasu-cialo"' in t


def test_oob_os_czasu(zalogowany, analiza):
    t = zalogowany.get(reverse("analizy:wzbogacenie", args=[analiza.pk]) + "?wiadomosc=0").content.decode()
    assert 'id="os-czasu-cialo" hx-swap-oob="true"' in t
    assert zalogowany.get(reverse("analizy:wzbogacenie", args=[analiza.pk]) + "?wiadomosc=9").status_code == 404


def test_mieszane_strefy_bez_500(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    hopy = w["analiza"]["0"]["received"]
    hopy[0]["czas"] = "2026-10-26T09:59:00"           # nagłówek z -0000 (bez strefy)
    hopy[1]["czas"] = "2026-10-26T10:00:00+00:00"
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    for sekcja_ in ("wiadomosc", "received"):
        r = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk]) + f"?sekcja={sekcja_}")
        assert r.status_code == 200
    assert zalogowany.get(reverse("analizy:wzbogacenie", args=[analiza.pk]) + "?wiadomosc=0").status_code == 200
    assert "2026-10-26 10:59:00 +0100" in sekcja(zalogowany, analiza)  # UTC pokazane w czasie Europe/Warsaw


def test_geo_ip_niekanoniczne_i_bez_artefaktu(zalogowany, analiza):
    w = copy.deepcopy(analiza.wynik)
    w["analiza"]["0"]["received"][0]["ip"] = "2001:4860:0:0::8888"
    w["analiza"]["0"]["received"][1]["ip"] = "8.8.4.4"  # publiczne, ale bez artefaktu
    Analiza.objects.filter(pk=analiza.pk).update(wynik=w)
    t = sekcja(zalogowany, analiza).split('id="os-czasu-cialo"')[1]
    assert "pulsuje" not in t
