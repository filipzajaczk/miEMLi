import re

import pytest
from django.urls import reverse

from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


def dyrektywy(naglowek: str) -> dict[str, str]:
    return {d.strip().split(" ", 1)[0]: d.strip() for d in naglowek.split(";") if d.strip()}


@pytest.mark.parametrize("nazwa,args", [("analizy:lista", []), ("login", [])])
def test_csp_na_stronach(client, zalogowany, nazwa, args):
    csp = dyrektywy(zalogowany.get(reverse(nazwa, args=args))["Content-Security-Policy"])
    assert csp["script-src"] == "script-src 'self'"
    assert "'unsafe-inline'" not in csp["style-src"]
    assert csp["object-src"] == "object-src 'none'"
    assert csp["frame-ancestors"] == "frame-ancestors 'self'"


def test_csp_na_ekranie_analizy(zalogowany, analiza):
    for sekcja in ("wiadomosc", "ioc"):
        r = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk]) + f"?sekcja={sekcja}")
        assert "script-src 'self'" in r["Content-Security-Policy"]


def test_brak_skryptow_i_stylow_inline(zalogowany, analiza):
    stron = [
        zalogowany.get(reverse("analizy:lista")).content.decode(),
        zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk]) + "?sekcja=ioc").content.decode(),
        zalogowany.get(reverse("analizy:opcje", args=[analiza.pk])).content.decode(),
    ]
    for t in stron:
        assert not re.search(r"\son[a-z]+=", t), "obsługa zdarzeń inline"
        assert ' style="' not in t
        assert not re.search(r"<script(?![^>]*\ssrc=)", t), "skrypt inline"
        assert "<style" not in t


def test_podglad_csp_z_sandbox(zalogowany, analiza):
    csp = zalogowany.get(reverse("analizy:podglad", args=[analiza.pk, "0"]))["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "sandbox" in dyrektywy(csp)


def test_podglad_czysci_ponownie_zapisany_html(zalogowany, analiza):
    # starszy (lub błędny) sanitizer mógł zapisać niebezpieczny HTML — podgląd czyści go jeszcze raz
    analiza.wynik["wiadomosc"]["html_bezpieczny"] = '<p>ok</p><script>alert(1)</script><img src="http://evil.example/p.gif">'
    analiza.save()
    t = zalogowany.get(reverse("analizy:podglad", args=[analiza.pk, "0"])).content.decode()
    assert "<p>ok</p>" in t and "<script" not in t and "evil.example" not in t


def test_rq_serializacja_json(settings):
    assert settings.RQ_QUEUES["default"]["SERIALIZER"] == "rq.serializers.JSONSerializer"


def test_web_bez_kluczy_zna_wlaczonych_dostawcow(settings):
    from analizy.zadania import skonfigurowany

    settings.GTI_API_KEY = ""
    settings.GTI_WLACZONE = True
    settings.CENSYS_API_TOKEN = ""
    settings.CENSYS_WLACZONE = False
    assert skonfigurowany("gti") is True and skonfigurowany("censys") is False
