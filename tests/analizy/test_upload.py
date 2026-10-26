import base64
import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from analizy.models import Analiza

pytestmark = pytest.mark.django_db


def plik(nazwa, dane):
    return SimpleUploadedFile(nazwa, dane, content_type="message/rfc822")


def test_upload_wymaga_logowania(client, probka):
    r = client.post(reverse("analizy:upload"), {"plik": plik("a.eml", probka("zip_exe"))})
    assert r.status_code == 302
    assert r.url.startswith(reverse("login"))
    assert Analiza.objects.count() == 0


def test_upload_ok(zalogowany, probka):
    r = zalogowany.post(reverse("analizy:upload"), {"plik": plik("a.eml", probka("zip_exe"))})
    analiza = Analiza.objects.get()
    assert r.status_code == 302
    assert r.url == reverse("analizy:szczegoly", args=[analiza.pk])


def test_upload_nie_mail(zalogowany):
    r = zalogowany.post(reverse("analizy:upload"), {"plik": plik("a.png", b"\x89PNG\r\n\x1a\n\x00")})
    assert r.status_code == 200
    assert "Plik nie jest prawidłową wiadomością .eml ani .msg." in r.content.decode()


def test_upload_za_duzy(zalogowany, settings):
    settings.MAKS_ROZMIAR_PLIKU = 10
    r = zalogowany.post(reverse("analizy:upload"), {"plik": plik("a.eml", b"From: a@b.pl\r\n\r\n" + b"x" * 20)})
    assert "Plik jest większy niż 50 MB." in r.content.decode()


def test_upload_bez_pliku(zalogowany):
    r = zalogowany.post(reverse("analizy:upload"), {})
    assert r.status_code == 200
    assert Analiza.objects.count() == 0


def test_lista_pokazuje_analizy(zalogowany, probka):
    zalogowany.post(reverse("analizy:upload"), {"plik": plik("faktura_marzec.eml", probka("zip_exe"))})
    r = zalogowany.get(reverse("analizy:lista"))
    assert "faktura_marzec.eml" in r.content.decode()


def test_brak_oryginalu_w_bazie(zalogowany, probka):
    from tests.samples.generuj_probki import EXE, zip_zwykly

    zalogowany.post(reverse("analizy:upload"), {"plik": plik("a.eml", probka("zip_exe"))})
    fragment = base64.b64encode(zip_zwykly("faktura.exe", EXE))[:40].decode()
    assert fragment in probka("zip_exe").decode()  # próbka faktycznie zawiera te bajty
    assert fragment not in json.dumps(Analiza.objects.get().wynik)
