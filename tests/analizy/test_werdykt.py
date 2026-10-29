import pytest
from django.urls import reverse

from analizy.models import Zdarzenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


def ustaw(klient, a, wartosc):
    return klient.post(reverse("analizy:werdykt", args=[a.pk]), {"werdykt": wartosc})


def test_ustawienie_werdyktu(zalogowany, analiza):
    r = ustaw(zalogowany, analiza, "phishing")
    assert r.status_code == 200 and "<html" not in r.content.decode()
    analiza.refresh_from_db()
    assert analiza.werdykt == "phishing"
    z = Zdarzenie.objects.get(typ="werdykt")
    assert z.szczegoly == {"z": "", "na": "phishing"} and z.analiza == analiza


def test_ten_sam_werdykt_bez_zdarzenia(zalogowany, analiza):
    ustaw(zalogowany, analiza, "spam")
    ustaw(zalogowany, analiza, "spam")
    assert Zdarzenie.objects.filter(typ="werdykt").count() == 1


@pytest.mark.parametrize("zla", ["<script>", "zlosliwy", "PHISHING"])
def test_zly_werdykt_400(zalogowany, analiza, zla):
    assert ustaw(zalogowany, analiza, zla).status_code == 400
    analiza.refresh_from_db()
    assert analiza.werdykt == ""


def test_werdykt_wymaga_logowania(client, analiza):
    r = ustaw(client, analiza, "spam")
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_get_405(zalogowany, analiza):
    assert zalogowany.get(reverse("analizy:werdykt", args=[analiza.pk])).status_code == 405


def test_przelacznik_na_ekranie(zalogowany, analiza):
    ustaw(zalogowany, analiza, "czysty")
    t = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk])).content.decode()
    assert 'hx-trigger="change"' in t and '<option value="czysty" selected>' in t


def test_kolumna_na_liscie(zalogowany, analiza):
    ustaw(zalogowany, analiza, "phishing")
    t = zalogowany.get(reverse("analizy:lista")).content.decode()
    assert ">Werdykt<" in t and '<span class="b bad">Phishing</span>' in t


def test_filtr_listy(zalogowany, probka, analityk):
    a1 = utworz_lub_otworz(probka("phishing_klasyczny"), "phish.eml", analityk)[0]
    a2 = utworz_lub_otworz(probka("zip_exe"), "spam.eml", analityk)[0]
    utworz_lub_otworz(probka("safelinks"), "bez.eml", analityk)
    a1.werdykt = "phishing"; a1.save()
    a2.werdykt = "spam"; a2.save()

    def lista(param):
        return zalogowany.get(reverse("analizy:lista") + param).content.decode()

    t = lista("?werdykt=phishing")
    assert "phish.eml" in t and "spam.eml" not in t and "bez.eml" not in t
    t = lista("?werdykt=brak")
    assert "bez.eml" in t and "phish.eml" not in t
    t = lista("?werdykt=xyz")
    assert all(n in t for n in ("phish.eml", "spam.eml", "bez.eml"))
    assert 'class="on"' in lista("?werdykt=spam")
