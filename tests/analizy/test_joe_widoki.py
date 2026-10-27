import re

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from analizy import joe_zadania as jz
from analizy.klucze_joe import nowa_para, zaszyfruj_klucz
from analizy.models import Analiza, ZgloszenieJoe, profil_dla
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def srodowisko(settings, monkeypatch):
    settings.JOE_KLUCZ_PUBLICZNY, settings.JOE_KLUCZ_PRYWATNY = nowa_para()
    monkeypatch.setattr(jz, "_kolejkuj", lambda *a, **kw: None)


@pytest.fixture
def z_kluczem(analityk):
    p = profil_dla(analityk)
    p.joe_klucz_szyfr = zaszyfruj_klucz(analityk.pk, "KluczJoe1234567890abcd")
    p.save()
    return analityk


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


def sekcja_joe(klient, a):
    return klient.get(reverse("analizy:szczegoly", args=[a.pk]) + "?sekcja=joe").content.decode()


def wyslij(klient, a, dane):
    return klient.post(reverse("analizy:joe_wyslij", args=[a.pk]), {"plik": SimpleUploadedFile("x.eml", dane)})


def test_menu_joe_otwiera_sekcje(zalogowany, analiza):
    t = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk])).content.decode()
    nav = t[t.find('<nav class="nav">'):t.find("</nav>")]
    assert re.search(r'class="nav-joe[^"]*"[^>]*hx-get="\?sekcja=joe', nav) or \
        re.search(r'hx-get="\?sekcja=joe[^"]*"[^>]*class="nav-joe', nav)
    assert "jbxcloud" not in nav


def test_sekcja_bez_klucza(zalogowany, analiza):
    t = sekcja_joe(zalogowany, analiza)
    assert "Ustaw klucz Joe w profilu" in t and 'href="/profil/"' in t
    assert re.search(r"<button[^>]*disabled", t)


def test_wyslij_ok(zalogowany, analiza, z_kluczem, probka, django_capture_on_commit_callbacks):
    t = sekcja_joe(zalogowany, analiza)
    assert "poza firmę" in t and "30 dniach" in t and "data-potwierdz" in t
    with django_capture_on_commit_callbacks(execute=True):
        r = wyslij(zalogowany, analiza, probka("phishing_klasyczny"))
    assert r.status_code == 302 and r.url.endswith("?sekcja=joe")
    assert ZgloszenieJoe.objects.filter(analiza=analiza).count() == 1


def test_wyslij_inny_plik(zalogowany, analiza, z_kluczem):
    r = wyslij(zalogowany, analiza, b"From: a@b\r\n\r\ninny")
    assert r.status_code == 200 and "To nie jest ten sam plik co w analizie." in r.content.decode()
    assert not ZgloszenieJoe.objects.exists()


def test_podwojne_klikniecie(zalogowany, analiza, z_kluczem, probka):
    wyslij(zalogowany, analiza, probka("phishing_klasyczny"))
    r = wyslij(zalogowany, analiza, probka("phishing_klasyczny"))
    assert "Już wysłano — poczekaj na wynik." in r.content.decode()
    assert ZgloszenieJoe.objects.count() == 1


def test_historia_odswiezanie(zalogowany, analiza, analityk):
    z = ZgloszenieJoe.objects.create(analiza=analiza, uzytkownik=analityk, status="trwa", webid="123")
    t = sekcja_joe(zalogowany, analiza)
    assert 'hx-trigger="every 5s"' in t and analityk.username in t
    assert 'href="https://jbxcloud.joesecurity.org/analysis/123" target="_blank" rel="noopener noreferrer"' in t
    ZgloszenieJoe.objects.filter(pk=z.pk).update(status="zakonczone", werdykt="zlosliwy", wynik=87)
    t = zalogowany.get(reverse("analizy:joe_historia", args=[analiza.pk])).content.decode()
    assert "every 5s" not in t and "złośliwy" in t and "87" in t and "<html" not in t


def upload(klient, dane, do_joe):
    pola = {"plik": SimpleUploadedFile("faktura.eml", dane)}
    if do_joe:
        pola["do_joe"] = "on"
    return klient.post(reverse("analizy:upload"), pola)


def test_checkbox_przy_uploadzie(zalogowany, z_kluczem, probka, django_capture_on_commit_callbacks):
    t = zalogowany.get(reverse("analizy:lista")).content.decode()
    assert 'name="do_joe"' in t and "Wyślij też do Joe Sandbox" in t and "data-potwierdz" in t
    with django_capture_on_commit_callbacks(execute=True):
        r = upload(zalogowany, probka("zip_exe"), True)
    assert r.url.endswith("?sekcja=joe") and ZgloszenieJoe.objects.count() == 1
    upload(zalogowany, probka("phishing_klasyczny"), False)
    assert ZgloszenieJoe.objects.count() == 1


def test_checkbox_bez_klucza(zalogowany, probka):
    r = upload(zalogowany, probka("zip_exe"), True)
    a = Analiza.objects.get()
    assert r.url.endswith("?sekcja=joe")
    assert "Ustaw klucz Joe w profilu." in sekcja_joe(zalogowany, a)
    assert "Ustaw klucz Joe w profilu." not in sekcja_joe(zalogowany, a).split("Wyślij cały mail")[0]


def test_endpointy_wymagaja_logowania(client, analiza):
    for url in (reverse("analizy:joe_historia", args=[analiza.pk]),):
        assert client.get(url).status_code == 302
    r = client.post(reverse("analizy:joe_wyslij", args=[analiza.pk]))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_joe_wyslij_get_405(zalogowany, analiza):
    assert zalogowany.get(reverse("analizy:joe_wyslij", args=[analiza.pk])).status_code == 405


def test_csp_bez_inline(zalogowany, analiza):
    t = sekcja_joe(zalogowany, analiza)
    assert not re.search(r"\son[a-z]+=", t) and ' style="' not in t
    assert not re.search(r"<script(?![^>]*\ssrc=)", t)
