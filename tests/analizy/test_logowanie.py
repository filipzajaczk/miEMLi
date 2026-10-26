import pytest
from django.urls import reverse


def test_lista_wymaga_logowania(client):
    r = client.get(reverse("analizy:lista"))
    assert r.status_code == 302
    assert r.url.startswith(reverse("login"))


@pytest.mark.django_db
def test_strona_logowania_po_polsku(client):
    r = client.get(reverse("login"))
    assert r.status_code == 200
    assert "Zaloguj" in r.content.decode()


@pytest.mark.django_db
def test_zalogowany_widzi_liste(client, django_user_model):
    u = django_user_model.objects.create_user("anna", password="x" * 12)
    client.force_login(u)
    r = client.get(reverse("analizy:lista"))
    assert r.status_code == 200
    assert "miemli" in r.content.decode()
