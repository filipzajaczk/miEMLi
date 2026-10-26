import pytest

from analizy.models import Analiza, Zdarzenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


def test_tworzy_analize_i_ioc(probka, analityk):
    analiza, utworzona = utworz_lub_otworz(probka("zip_exe"), "zip_exe.eml", analityk)
    assert utworzona is True
    assert analiza.ioc.count() == 4
    exe = analiza.ioc.get(etykieta="faktura.exe")
    assert exe.rodzic == analiza.ioc.get(etykieta="faktura.zip")
    assert Zdarzenie.objects.filter(analiza=analiza, typ="utworzenie", uzytkownik=analityk).exists()
    assert analiza.wynik["wiadomosc"]["temat"] == "Faktura"


def test_deduplikacja_ten_sam_ticket(probka, analityk):
    a1, u1 = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=1, attachment_id=5)
    a2, u2 = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=1, attachment_id=5)
    assert a1.pk == a2.pk
    assert (u1, u2) == (True, False)
    assert Analiza.objects.count() == 1


def test_deduplikacja_upload_bez_ticketu(probka, analityk):
    a1, _ = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk)
    a2, utworzona = utworz_lub_otworz(probka("zip_exe"), "b.eml", analityk)
    assert a1.pk == a2.pk and utworzona is False


def test_inny_ticket_nowa_analiza(probka, analityk):
    a1, _ = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=1)
    a2, _ = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk, ticket_id=2)
    assert a1.pk != a2.pk


def test_ignorowane_domeny_z_ustawien(probka, analityk, settings):
    settings.MIEMLI_IGNOROWANE_DOMENY = frozenset({"evil.example"})
    analiza, _ = utworz_lub_otworz(probka("zip_exe"), "a.eml", analityk)
    assert not analiza.ioc.filter(typ="domena").exists()


def test_nul_w_tresci_i_naglowkach(analityk):
    dane = (b"From: a@x.pl\r\nSubject: a\x00b\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\naGkAdGhlcmU=\r\n")
    analiza, _ = utworz_lub_otworz(dane, "nul.eml", analityk)
    analiza.refresh_from_db()
    assert analiza.wynik["wiadomosc"]["tekst"].startswith("hi")


def test_bardzo_dlugi_url(analityk, zbuduj_mail):
    import base64
    import os

    url = "http://evil.example/?t=" + base64.b64encode(os.urandom(3000)).decode()
    analiza, _ = utworz_lub_otworz(zbuduj_mail(tekst=url), "dlugi.eml", analityk)
    assert analiza.ioc.filter(typ="url").count() == 1
