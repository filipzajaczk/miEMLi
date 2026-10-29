import re

import pytest
from django.urls import reverse

from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


def widoczny(klient, url):
    html = klient.get(url).content.decode()
    html = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S)
    return re.sub(r"<[^>]+>", " ", html)


def test_nazwa_artefakty(zalogowany, probka, analityk):
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    szczegoly = reverse("analizy:szczegoly", args=[a.pk])
    t = widoczny(zalogowany, szczegoly)
    assert re.search(r"Artefakty · \d+", t)
    assert "Artefakty" in widoczny(zalogowany, szczegoly + "?sekcja=ioc")
    for url in (reverse("analizy:lista"), szczegoly, szczegoly + "?sekcja=ioc"):
        assert "IOC" not in widoczny(zalogowany, url), url
    dymek = re.search(r'title="Sprawdź ponownie[^"]*"', zalogowany.get(szczegoly).content.decode()).group(0)
    assert "IOC" not in dymek


def test_pusta_lista_artefaktow(zalogowany, probka, analityk):
    a = utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]
    a.ioc.all().delete()
    t = widoczny(zalogowany, reverse("analizy:szczegoly", args=[a.pk]) + "?sekcja=ioc")
    assert "Nie znaleziono artefaktów." in t
