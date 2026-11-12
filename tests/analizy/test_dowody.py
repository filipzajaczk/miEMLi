"""Lista dowodów na ekranie analizy: sygnały z analizy i wyniki GTI ułożone według wagi."""

import time
from types import SimpleNamespace

from analizy.prezentacja import WidokWzbogacenia, dowody, grupy_dowodow


def _w(**pola):
    return {"zalaczniki": [], "obrazki": [], "ostrzezenia": [], **pola}


def _a(spf="pass", dkim="pass", dmarc="pass", sygnaly=(), received=(), linki=()):
    return {"uwierzytelnienie": {"spf": spf, "dkim": dkim, "dmarc": dmarc}, "sygnaly": list(sygnaly),
            "received": list(received), "linki": list(linki)}


def _ioc(pk, typ, wartosc, etykieta=None, rodzic=None):
    return SimpleNamespace(pk=pk, typ=typ, wartosc=wartosc, etykieta=etykieta, rodzic=rodzic)


def _gti(**skrot):
    return {"gti": WidokWzbogacenia("gotowe", skrot)}


def test_czysty_mail_bez_dowodow():
    assert dowody(_w(), _a(), [], {}) == []


def test_nieudane_uwierzytelnienie_jednym_dowodem():
    d = dowody(_w(), _a(spf="fail", dmarc="fail"), [], {})
    assert len(d) == 1
    assert d[0].poziom == "wysokie" and d[0].co == "SPF i DMARC nie przeszły" and d[0].sekcja == "naglowki"


def test_brak_wyniku_uwierzytelnienia_informacyjnie():
    d = dowody(_w(), _a(dkim="none", dmarc=None), [], {})
    assert [(x.poziom, x.co) for x in d] == [("info", "Brak wyniku: DKIM, DMARC")]


def test_sygnaly_z_poziomami():
    d = dowody(_w(), _a(sygnaly=[
        {"kod": "DARMOWA_POCZTA", "opis": "Adres w darmowej poczcie: gmail.com."},
        {"kod": "DOMENA_PODOBNA", "opis": "pko-platnosci.example przypomina pkobp.pl."},
        {"kod": "REPLY_TO_INNA_DOMENA", "opis": "Odpowiedź trafi do x@gmail.com."},
    ]), [], {})
    assert [x.poziom for x in d] == ["wysokie", "srednie", "info"]
    assert d[0].gdzie == "pko-platnosci.example przypomina pkobp.pl."


def test_nieznany_sygnal_sredni_z_opisem():
    d = dowody(_w(), _a(sygnaly=[{"kod": "NOWY", "opis": "Coś nowego."}]), [], {})
    assert d[0].poziom == "srednie" and d[0].co == "Coś nowego."


def test_anomalie_hopow():
    hopy = [{"uwagi": []}, {"uwagi": [{"kod": "CZAS_WSTECZ", "opis": "Czas cofa się o 5 min."},
                                     {"kod": "BRAK_IP", "opis": "Brak adresu IP."}]}]
    d = dowody(_w(), _a(received=hopy), [], {})
    assert len(d) == 1 and d[0].gdzie == "Serwer 2: Czas cofa się o 5 min." and d[0].sekcja == "received"


def test_niezgodne_linki_zliczone():
    linki = [{"niezgodny": True, "docelowy": "https://zly.example/a"}, {"niezgodny": True, "docelowy": "https://b.example"},
             {"niezgodny": False, "docelowy": "https://ok.example"}]
    d = dowody(_w(), _a(linki=linki), [], {})
    assert len(d) == 1 and d[0].co == "2 linki prowadzą gdzie indziej, niż mówi tekst"
    assert "hxxps://zly[.]example" in d[0].gdzie


def test_zaszyfrowany_zalacznik_w_archiwum():
    zip_ = {"nazwa": "a.zip", "zaszyfrowany": False, "dzieci": [{"nazwa": "b.7z", "zaszyfrowany": True, "dzieci": []}]}
    d = dowody(_w(zalaczniki=[zip_]), _a(), [], {})
    assert d[0].poziom == "wysokie" and d[0].gdzie == "b.7z" and d[0].sekcja == "zalaczniki"


def test_podejrzane_obrazki():
    obrazki = [{"nazwa": "x.png", "uwagi": [{"kod": "FORMAT_NIEZGODNY"}]}, {"nazwa": "y.png", "uwagi": []}]
    d = dowody(_w(obrazki=obrazki), _a(), [], {})
    assert len(d) == 1 and d[0].gdzie == "x.png"


def test_ostrzezenia_parsera_informacyjnie():
    d = dowody(_w(ostrzezenia=[{"kod": "LIMIT", "opis": "Pominięto część archiwum."}]), _a(), [], {})
    assert d[0].poziom == "info" and d[0].co == "Pominięto część archiwum."


def test_gti_zlosliwy_plik_krytyczny_z_archiwum():
    zip_ = _ioc(1, "plik", "a" * 64, "faktura.zip")
    exe = _ioc(2, "plik", "b" * 64, "faktura.exe", rodzic=zip_)
    wz = {1: _gti(werdykt="podejrzany"), 2: _gti(werdykt="zlosliwy", wykrycia=[41, 70])}
    d = dowody(_w(), _a(), [(zip_, 0), (exe, 1)], wz)
    assert [(x.poziom, x.co) for x in d] == [("krytyczne", "faktura.exe: złośliwy w GTI"),
                                            ("wysokie", "faktura.zip: podejrzany w GTI")]
    assert d[0].gdzie == "41/70 wykryć, w faktura.zip" and d[0].sekcja == "ioc"


def test_gti_pojedyncze_wykrycia_srednie_i_rozbrojone():
    url = _ioc(1, "url", "https://zly.example/x")
    d = dowody(_w(), _a(), [(url, 0)], {1: _gti(werdykt="nieszkodliwy", wykrycia=[2, 94])})
    assert d[0].poziom == "srednie" and d[0].co == "hxxps://zly[.]example/x: pojedyncze wykrycia w GTI"


def test_gti_czysty_i_nieskonczony_bez_dowodu():
    ip = _ioc(1, "ip", "1.2.3.4")
    dom = _ioc(2, "domena", "a.example")
    wz = {1: _gti(werdykt="nieszkodliwy", wykrycia=[0, 94]), 2: {"gti": WidokWzbogacenia("oczekuje")}}
    assert dowody(_w(), _a(), [(ip, 0), (dom, 0)], wz) == []


def test_nowa_domena_wysokie():
    dom = _ioc(1, "domena", "nowa.example")
    d = dowody(_w(), _a(), [(dom, 0)], {1: _gti(werdykt="nieszkodliwy", utworzono=time.time() - 3 * 86400)})
    assert [(x.poziom, x.co) for x in d] == [("wysokie", "Domena nowa[.]example ma 3 dni")]


def test_grupy_w_kolejnosci_wagi_bez_pustych():
    d = dowody(_w(), _a(spf="fail", sygnaly=[{"kod": "DARMOWA_POCZTA", "opis": "x"}]), [], {})
    assert [(kod, nazwa, len(lista)) for kod, nazwa, lista in grupy_dowodow(d)] == [
        ("wysokie", "Wysokie", 1), ("info", "Informacyjne", 1)]


# --- widoki -------------------------------------------------------------------------------------

import pytest  # noqa: E402
from django.urls import reverse  # noqa: E402

from analizy.uslugi import utworz_lub_otworz  # noqa: E402


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "p.eml", analityk)[0]


@pytest.mark.django_db
def test_ekran_pokazuje_dowody(zalogowany, analiza):
    t = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk])).content.decode()
    dowody_html = t[t.find('id="dowody"'):t.find('class="decyzja"')]
    assert "SPF i DMARC nie przeszły" in dowody_html and "Odpowiedzi trafią do innej domeny" in dowody_html
    assert 'hx-get="?sekcja=naglowki&wiadomosc=0"' in dowody_html


@pytest.mark.django_db
def test_zmiana_zakladki_odswieza_dowody_oob(zalogowany, analiza):
    r = zalogowany.get(reverse("analizy:szczegoly", args=[analiza.pk]) + "?sekcja=linki", HTTP_HX_REQUEST="true")
    t = r.content.decode()
    assert "<html" not in t and 'id="dowody" class="dowody" hx-swap-oob="true"' in t
    assert "SPF i DMARC nie przeszły" in t


@pytest.mark.django_db
def test_odpytywanie_odswieza_dowody(zalogowany, analiza):
    t = zalogowany.get(reverse("analizy:wzbogacenie", args=[analiza.pk]) + "?wiadomosc=0").content.decode()
    assert 'id="dowody" class="dowody" hx-swap-oob="true"' in t and "SPF i DMARC nie przeszły" in t
