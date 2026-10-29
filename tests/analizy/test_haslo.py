import pytest
from django.contrib.auth import authenticate
from django.test import Client
from django.urls import reverse

from analizy.models import Zdarzenie

pytestmark = pytest.mark.django_db
STARE = "x" * 12
NOWE = "Nowe-Haslo-Analityka-2026!"


def zmien(klient, stare=STARE, nowe=NOWE, powtorz=None):
    return klient.post(reverse("haslo"), {"old_password": stare, "new_password1": nowe,
                                          "new_password2": powtorz if powtorz is not None else nowe})


def test_zmiana_hasla(zalogowany, analityk):
    r = zmien(zalogowany)
    assert r.status_code == 302 and r.url == reverse("profil")
    assert authenticate(username="anna", password=NOWE) is not None
    assert authenticate(username="anna", password=STARE) is None
    assert "Hasło zostało zmienione." in zalogowany.get(reverse("profil")).content.decode()
    assert "Hasło zostało zmienione." not in zalogowany.get(reverse("profil")).content.decode()
    z = Zdarzenie.objects.get(typ="haslo_zmienione")
    assert NOWE not in str(z.szczegoly) and STARE not in str(z.szczegoly)


def test_inne_sesje_wylogowane(analityk):
    pierwszy, drugi = Client(), Client()
    pierwszy.login(username="anna", password=STARE)
    drugi.login(username="anna", password=STARE)
    zmien(pierwszy)
    assert pierwszy.get(reverse("analizy:lista")).status_code == 200
    r = drugi.get(reverse("analizy:lista"))
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


@pytest.mark.parametrize("stare,nowe,powtorz", [
    ("zle-haslo-123", NOWE, NOWE), (STARE, NOWE, NOWE + "x"), (STARE, "krotkie123", "krotkie123"),
])
def test_bledne_dane(zalogowany, analityk, stare, nowe, powtorz):
    r = zmien(zalogowany, stare, nowe, powtorz)
    assert r.status_code == 200
    assert authenticate(username="anna", password=STARE) is not None
    assert not Zdarzenie.objects.filter(typ="haslo_zmienione").exists()


def test_haslo_wymaga_logowania(client):
    r = zmien(client)
    assert r.status_code == 302 and r.url.startswith(reverse("login"))


def test_haslo_get_405(zalogowany):
    assert zalogowany.get(reverse("haslo")).status_code == 405


def test_formularz_w_profilu(zalogowany):
    t = zalogowany.get(reverse("profil")).content.decode()
    assert "Zmiana hasła" in t and 'name="old_password"' in t and 'autocomplete="current-password"' in t


def test_parametry_wrazliwe(analityk, rf):
    from analizy.profil import zmien_haslo

    zadanie = rf.post("/profil/haslo/", {"old_password": STARE, "new_password1": NOWE, "new_password2": NOWE})
    zadanie.user = analityk
    zadanie.session = {}
    try:
        zmien_haslo(zadanie)
    except Exception:
        pass  # brak pełnej sesji w RequestFactory — liczy się oznaczenie parametrów
    assert set(zadanie.sensitive_post_parameters) == {"old_password", "new_password1", "new_password2"}
