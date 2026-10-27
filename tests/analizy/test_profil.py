import pytest
from django.urls import reverse

from analizy.klucze_joe import nowa_para, odszyfruj_klucz
from analizy.models import Zdarzenie, profil_dla

pytestmark = pytest.mark.django_db
KLUCZ = "A" * 30 + "x7f3"


@pytest.fixture(autouse=True)
def para(settings):
    settings.JOE_KLUCZ_PUBLICZNY, settings.JOE_KLUCZ_PRYWATNY = nowa_para()


def zapisz(klient, klucz):
    return klient.post(reverse("profil"), {"akcja": "zapisz", "klucz_joe": klucz})


def test_profil_wymaga_logowania(client):
    r = client.get(reverse("profil"))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_zapis_klucza(zalogowany, analityk):
    r = zapisz(zalogowany, KLUCZ)
    assert r.status_code == 302 and r.url == reverse("profil")
    p = profil_dla(analityk)
    assert p.joe_klucz_koncowka == "x7f3" and p.joe_klucz_stan == "sprawdzanie"
    assert odszyfruj_klucz(analityk.pk, p.joe_klucz_szyfr) == KLUCZ
    z = Zdarzenie.objects.get(typ="joe_klucz_ustawiony")
    assert KLUCZ not in str(z.szczegoly)


def test_klucz_nigdy_w_html(zalogowany):
    zapisz(zalogowany, KLUCZ)
    t = zalogowany.get(reverse("profil")).content.decode()
    assert KLUCZ not in t and "…x7f3" in t
    assert 'type="password"' in t and 'autocomplete="off"' in t


@pytest.mark.parametrize("zly", ["krotki", "a" * 129, "klucz ze spacja 123456789012345"])
def test_zly_format(zalogowany, analityk, zly):
    t = zapisz(zalogowany, zly).content.decode()
    assert "Nieprawidłowy format klucza Joe." in t
    assert profil_dla(analityk).joe_klucz_szyfr is None


def test_usuniecie(zalogowany, analityk):
    zapisz(zalogowany, KLUCZ)
    zalogowany.post(reverse("profil"), {"akcja": "usun"})
    p = profil_dla(analityk)
    assert p.joe_klucz_szyfr is None and p.joe_klucz_koncowka == ""
    assert Zdarzenie.objects.filter(typ="joe_klucz_usuniety").exists()


def test_get_nie_zmienia(zalogowany, analityk):
    zalogowany.get(reverse("profil") + f"?akcja=zapisz&klucz_joe={KLUCZ}")
    assert profil_dla(analityk).joe_klucz_szyfr is None


def test_link_profilu_w_pasku(zalogowany):
    assert f'href="{reverse("profil")}"' in zalogowany.get(reverse("analizy:lista")).content.decode()
