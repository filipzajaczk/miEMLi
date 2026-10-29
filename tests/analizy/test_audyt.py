import logging
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from analizy.models import Zdarzenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin(django_user_model):
    return django_user_model.objects.create_user("szef", password="x" * 12, is_staff=True)


@pytest.fixture
def jako_admin(client, admin):
    client.force_login(admin)
    return client


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


def test_audyt_dla_admina(jako_admin, analiza, analityk):
    Zdarzenie.objects.create(uzytkownik=analityk, analiza=analiza, typ="werdykt",
                             szczegoly={"z": "", "na": "phishing"})
    t = jako_admin.get(reverse("audyt")).content.decode()
    assert "Zmiana werdyktu" in t and "anna" in t
    assert reverse("analizy:szczegoly", args=[analiza.pk]) in t


@pytest.mark.parametrize("param", ["", "?typ=werdykt", "?uzytkownik=1&od=2020-01-01"])
def test_audyt_zwykly_uzytkownik_403(zalogowany, analiza, admin, caplog, param):
    Zdarzenie.objects.create(uzytkownik=admin, typ="haslo_zmienione")
    with caplog.at_level(logging.WARNING):
        r = zalogowany.get(reverse("audyt") + param)
    assert r.status_code == 403
    assert "szef" not in r.content.decode()
    assert "Odmowa dostępu do audytu: anna" in caplog.text


def test_audyt_wymaga_logowania(client):
    r = client.get(reverse("audyt"))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_filtry(jako_admin, analityk, admin, analiza):
    z1 = Zdarzenie.objects.create(uzytkownik=analityk, analiza=analiza, typ="werdykt")
    z2 = Zdarzenie.objects.create(uzytkownik=admin, typ="haslo_zmienione")
    Zdarzenie.objects.filter(pk=z2.pk).update(czas=timezone.now() - timedelta(days=10))

    def ile(param):
        return jako_admin.get(reverse("audyt") + param).context["strona"].paginator.count

    wszystkie = ile("")
    assert ile("?typ=werdykt") == Zdarzenie.objects.filter(typ="werdykt").count()
    assert ile(f"?uzytkownik={admin.pk}") == 1
    dzis = timezone.localdate().isoformat()
    assert ile(f"?od={dzis}") == wszystkie - 1
    stara = (timezone.localdate() - timedelta(days=10)).isoformat()
    assert ile(f"?od={stara}&do={stara}") == 1
    assert ile("?od=zly-format&uzytkownik=abc") == wszystkie
    assert z1.pk


def test_paginacja(jako_admin, admin):
    Zdarzenie.objects.bulk_create(Zdarzenie(uzytkownik=admin, typ="otwarcie") for _ in range(60))
    assert len(jako_admin.get(reverse("audyt")).context["strona"].object_list) == 50
    assert len(jako_admin.get(reverse("audyt") + "?strona=2").context["strona"].object_list) == 10


def test_link_tylko_dla_admina(zalogowany, client, admin):
    assert reverse("audyt") not in zalogowany.get(reverse("analizy:lista")).content.decode()
    client.force_login(admin)
    assert reverse("audyt") in client.get(reverse("analizy:lista")).content.decode()


def test_usunieta_analiza(jako_admin, admin):
    Zdarzenie.objects.create(uzytkownik=admin, typ="usuniecie", szczegoly={"plik": "stary.eml"})
    t = jako_admin.get(reverse("audyt")).content.decode()
    assert "Usunięcie analizy" in t and "stary.eml" in t


def test_nieznany_typ_surowy(jako_admin, admin):
    Zdarzenie.objects.create(uzytkownik=admin, typ="cos_nowego")
    assert "cos_nowego" in jako_admin.get(reverse("audyt")).content.decode()
