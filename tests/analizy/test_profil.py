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


def test_klucz_ukryty_w_raportach_bledow(analityk, rf):
    from analizy.profil import profil as widok

    zadanie = rf.post("/profil/", {"akcja": "zapisz", "klucz_joe": KLUCZ})
    zadanie.user = analityk
    zadanie.session = {}
    widok(zadanie)
    assert list(zadanie.sensitive_post_parameters) == ["klucz_joe"]


def test_ustawienia_z_kluczami_ukryte(settings):
    from django.views.debug import get_default_exception_reporter_filter

    settings.JOE_KLUCZ_PRYWATNY = "TAJNE"
    bezpieczne = get_default_exception_reporter_filter().get_safe_settings()
    assert bezpieczne["JOE_KLUCZ_PRYWATNY"] != "TAJNE"


def test_joe_nieskonfigurowany_w_profilu(zalogowany, settings):
    settings.JOE_KLUCZ_PUBLICZNY = ""
    t = zalogowany.get(reverse("profil")).content.decode()
    assert "nie jest skonfigurowana" in t and 'name="klucz_joe"' not in t
    assert zapisz(zalogowany, KLUCZ).status_code == 200


def test_sprawdzanie_nie_wisi_gdy_redis_niedostepny(zalogowany, analityk, monkeypatch):
    from analizy import profil as modul

    monkeypatch.setattr(modul, "zlec_sprawdzenie_klucza", lambda uid: False)
    zapisz(zalogowany, KLUCZ)
    assert profil_dla(analityk).joe_klucz_stan == "nieznany"
