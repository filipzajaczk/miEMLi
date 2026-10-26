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
