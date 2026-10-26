import pytest
from django.urls import reverse

from analizy.models import IOC, Analiza, Zdarzenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("zip_exe"), "faktura_marzec.eml", analityk)[0]


def test_wiersz_listy_rozwijany(zalogowany, analiza):
    t = zalogowany.get(reverse("analizy:lista")).content.decode()
    assert f'data-szczegoly="{reverse("analizy:opcje", args=[analiza.pk])}"' in t
    assert f'data-cel="opcje-{analiza.pk}"' in t


def test_opcje_pokazuja_komentarz_i_usuwanie(zalogowany, analiza):
    analiza.notatka = "Potwierdzony phishing <b>pilne</b>"
    analiza.save()
    t = zalogowany.get(reverse("analizy:opcje", args=[analiza.pk])).content.decode()
    assert "<textarea" in t and "Potwierdzony phishing &lt;b&gt;pilne&lt;/b&gt;" in t
    assert reverse("analizy:notatka", args=[analiza.pk]) in t
    assert reverse("analizy:usun", args=[analiza.pk]) in t
    assert "confirm(" in t


def test_zapis_komentarza(zalogowany, analiza, analityk):
    r = zalogowany.post(reverse("analizy:notatka", args=[analiza.pk]), {"notatka": "Zgłoszone do RTIR"})
    assert r.status_code == 200 and "Zapisano" in r.content.decode()
    analiza.refresh_from_db()
    assert analiza.notatka == "Zgłoszone do RTIR"
    assert Zdarzenie.objects.filter(analiza=analiza, typ="notatka", uzytkownik=analityk).exists()


def test_komentarz_za_dlugi(zalogowany, analiza):
    r = zalogowany.post(reverse("analizy:notatka", args=[analiza.pk]), {"notatka": "x" * 10001})
    assert r.status_code == 200 and "maksymalnie 10000" in r.content.decode()
    analiza.refresh_from_db()
    assert analiza.notatka == ""


def test_usuniecie_analizy(zalogowany, analiza, analityk):
    pk = analiza.pk
    r = zalogowany.post(reverse("analizy:usun", args=[pk]))
    assert r.status_code == 302 and r.url == reverse("analizy:lista")
    assert not Analiza.objects.filter(pk=pk).exists()
    assert not IOC.objects.filter(analiza_id=pk).exists()
    z = Zdarzenie.objects.get(typ="usuniecie")
    assert z.uzytkownik == analityk and z.analiza is None
    assert z.szczegoly["plik"] == "faktura_marzec.eml" and z.szczegoly["sha256"] == analiza.sha256


@pytest.mark.parametrize("nazwa", ["notatka", "usun"])
def test_get_405(zalogowany, analiza, nazwa):
    assert zalogowany.get(reverse(f"analizy:{nazwa}", args=[analiza.pk])).status_code == 405


@pytest.mark.parametrize("nazwa", ["opcje", "notatka", "usun"])
def test_wymaga_logowania(client, analiza, nazwa):
    r = client.post(reverse(f"analizy:{nazwa}", args=[analiza.pk])) if nazwa != "opcje" else \
        client.get(reverse(f"analizy:{nazwa}", args=[analiza.pk]))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))
    assert Analiza.objects.filter(pk=analiza.pk).exists()


def test_usuniecie_nieistniejacej_404(zalogowany):
    assert zalogowany.post(reverse("analizy:usun", args=[999])).status_code == 404
