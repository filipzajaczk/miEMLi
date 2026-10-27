import copy
import json
import logging

import httpx
import pytest
import respx
from django.urls import reverse

from analizy.models import Analiza, Zdarzenie
from analizy.piaskownica_klient import AnalizaPrzerwana, waliduj_wynik
from piaskownica.zadanie import analizuj_plik

pytestmark = pytest.mark.django_db
URL = "http://parser.test"


@pytest.fixture
def przez_siec(settings):
    settings.PIASKOWNICA_URL = URL


@pytest.fixture
def wynik_probki(probka):
    return analizuj_plik(probka("zip_exe"), "zip_exe.eml")["wynik"]


def upload(klient, dane=b"From: a@b.pl\r\n\r\nx", nazwa="a.eml"):
    from django.core.files.uploadedfile import SimpleUploadedFile

    return klient.post(reverse("analizy:upload"), {"plik": SimpleUploadedFile(nazwa, dane)})


@respx.mock
def test_web_nie_parsuje_lokalnie(zalogowany, przez_siec, wynik_probki, probka, monkeypatch):
    import mailcore.parsuj
    import piaskownica.zadanie

    def zakaz(*a, **kw):
        raise AssertionError("web parsuje lokalnie")

    monkeypatch.setattr(mailcore.parsuj, "parsuj", zakaz)
    monkeypatch.setattr(piaskownica.zadanie, "analizuj_plik", zakaz)
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "ok", "wynik": wynik_probki})
    r = upload(zalogowany, probka("zip_exe"))
    assert r.status_code == 302
    assert Analiza.objects.get().ioc.count() == 4


@pytest.mark.parametrize("powod,tekst", [
    ("czas", "przekroczony czas"), ("pamiec", "przekroczony limit pamięci"), ("awaria", "parser przerwał pracę"),
])
@respx.mock
def test_przerwana(zalogowany, przez_siec, powod, tekst, caplog):
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "przerwana", "powod": powod})
    caplog.set_level(logging.WARNING)
    t = upload(zalogowany).content.decode()
    assert tekst in t and "Joe Sandbox" in t
    z = Zdarzenie.objects.get(typ="analiza_przerwana")
    assert z.szczegoly["powod"] == powod and len(z.szczegoly["sha256"]) == 64 and z.analiza is None
    assert not Analiza.objects.exists()
    if powod == "awaria":
        assert any(r.levelno == logging.WARNING for r in caplog.records)


@pytest.mark.parametrize("odpowiedz", [
    httpx.Response(503),
    httpx.ConnectError("odmowa"),
    httpx.RemoteProtocolError("zerwane"),
    httpx.ReadTimeout("timeout"),
])
@respx.mock
def test_niedostepny(zalogowany, przez_siec, odpowiedz):
    trasa = respx.post(f"{URL}/analizuj")
    if isinstance(odpowiedz, Exception):
        trasa.mock(side_effect=odpowiedz)
    else:
        trasa.mock(return_value=odpowiedz)
    r = upload(zalogowany)
    assert r.status_code == 200 and "Sandbox analizy niedostępny" in r.content.decode()


@respx.mock
def test_nieobslugiwany_i_za_duzy(zalogowany, przez_siec):
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "przerwana", "powod": "nieobslugiwany"})
    assert "Plik nie jest prawidłową wiadomością" in upload(zalogowany).content.decode()
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "przerwana", "powod": "za_duzy"})
    assert "większy niż 50 MB" in upload(zalogowany).content.decode()


def _zepsuj(wynik, sposob):
    w = copy.deepcopy(wynik)
    if sposob == "brak_ioc":
        del w["ioc"]
    elif sposob == "ioc_str":
        w["ioc"] = "x"
    elif sposob == "za_duzo_ioc":
        w["ioc"] = [dict(w["ioc"][0], id=i + 1, rodzic_id=None) for i in range(5001)]
    elif sposob == "zly_typ":
        w["ioc"][0]["typ"] = "exe"
    elif sposob == "dluga_wartosc":
        w["ioc"][0]["wartosc"] = "x" * 9000
    elif sposob == "zly_rodzic":
        w["ioc"][0]["rodzic_id"] = w["ioc"][0]["id"]
    elif sposob == "wiadomosc_nie_dict":
        w["wiadomosc"] = []
    return w


@pytest.mark.parametrize("sposob", ["brak_ioc", "ioc_str", "za_duzo_ioc", "zly_typ", "dluga_wartosc",
                                    "zly_rodzic", "wiadomosc_nie_dict"])
def test_walidacja(wynik_probki, sposob):
    with pytest.raises(AnalizaPrzerwana) as e:
        waliduj_wynik(_zepsuj(wynik_probki, sposob))
    assert e.value.powod == "nieprawidlowa_odpowiedz"


def test_walidacja_poprawnego(wynik_probki):
    assert waliduj_wynik(wynik_probki) is wynik_probki


@respx.mock
def test_nie_json_i_za_duza_odpowiedz(zalogowany, przez_siec, monkeypatch):
    import analizy.piaskownica_klient as k

    respx.post(f"{URL}/analizuj").respond(200, content=b"<html>")
    assert "Nieprawidłowy wynik analizy" in upload(zalogowany).content.decode()
    monkeypatch.setattr(k, "MAKS_ODPOWIEDZ", 100)
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "ok", "wynik": {"x": "y" * 200}})
    assert "Nieprawidłowy wynik analizy" in upload(zalogowany).content.decode()


@respx.mock
def test_wrogi_wynik_wyswietlany_bezpiecznie(zalogowany, przez_siec, wynik_probki, probka):
    w = copy.deepcopy(wynik_probki)
    w["wiadomosc"]["temat"] = "<script>alert(1)</script>"
    url_ioc = {"id": len(w["ioc"]) + 1, "typ": "url", "wartosc": "javascript:alert(1)", "rodzic_id": None,
               "zrodlo": "tresc", "etykieta": "<img src=x onerror=alert(1)>", "hashe": None, "haslo_archiwum": None}
    w["ioc"].append(url_ioc)
    respx.post(f"{URL}/analizuj").respond(200, json={"status": "ok", "wynik": w})
    r = upload(zalogowany, probka("zip_exe"))
    t = zalogowany.get(r.url + "?sekcja=ioc").content.decode() + zalogowany.get(r.url).content.decode()
    assert "<script>alert" not in t and "&lt;script&gt;" in t
    assert 'href="javascript' not in t and "<img src=x" not in t


@respx.mock
def test_naglowek_nazwy(zalogowany, przez_siec, wynik_probki):
    trasa = respx.post(f"{URL}/analizuj").respond(200, json={"status": "ok", "wynik": wynik_probki})
    from analizy.piaskownica_klient import analizuj_w_piaskownicy

    analizuj_w_piaskownicy(b"x", "zażółć\r\nX-Evil: 1.eml")
    naglowki = trasa.calls.last.request.headers
    assert "\r" not in naglowki["X-Miemli-Nazwa"] and "\n" not in naglowki["X-Miemli-Nazwa"]
    assert "X-Evil" not in naglowki
    analizuj_w_piaskownicy(b"x", "a" * 1000)
    assert len(trasa.calls.last.request.headers["X-Miemli-Nazwa"]) <= 255


# --- z końcowego przeglądu ---

@respx.mock
def test_strumien_przerwany_po_limicie(zalogowany, przez_siec, monkeypatch):
    import analizy.piaskownica_klient as k

    monkeypatch.setattr(k, "MAKS_ODPOWIEDZ", 1000)
    respx.post(f"{URL}/analizuj").respond(200, stream=httpx.ByteStream(b"{" + b" " * 5000))
    assert "Nieprawidłowy wynik analizy" in upload(zalogowany).content.decode()


@respx.mock
def test_gleboko_zagniezdzony_json(zalogowany, przez_siec):
    respx.post(f"{URL}/analizuj").respond(200, content=b"[" * 100000 + b"]" * 100000)
    assert "Nieprawidłowy wynik analizy" in upload(zalogowany).content.decode()
    assert Zdarzenie.objects.filter(typ="analiza_przerwana", szczegoly__powod="nieprawidlowa_odpowiedz").exists()


@pytest.mark.parametrize("odpowiedz", [b"[1, 2]", b'"tekst"', b"null"])
@respx.mock
def test_zdrowie_nie_slownik(settings, odpowiedz):
    import analizy.piaskownica_klient as k

    settings.PIASKOWNICA_URL = URL
    k._stan_cache.update(czas=0.0, wartosc=None)
    respx.get(f"{URL}/zdrowie").respond(200, content=odpowiedz)
    assert k.stan_piaskownicy() is None


def test_pusty_url_na_produkcji_odmawia(zalogowany, settings, probka):
    settings.PIASKOWNICA_URL = ""
    settings.PIASKOWNICA_W_PROCESIE = False
    settings.DEBUG = False
    r = upload(zalogowany, probka("zip_exe"))
    assert "Sandbox analizy niedostępny" in r.content.decode()
    assert not Analiza.objects.exists()
