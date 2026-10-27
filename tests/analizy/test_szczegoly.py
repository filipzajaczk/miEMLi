import pytest
from django.urls import reverse

from analizy.models import Zdarzenie
from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db

CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox"


@pytest.fixture
def analiza(probka, analityk):
    def utworz(nazwa):
        return utworz_lub_otworz(probka(nazwa), f"{nazwa}.eml", analityk)[0]
    return utworz


def url(a, **params):
    from urllib.parse import urlencode
    return reverse("analizy:szczegoly", args=[a.pk]) + ("?" + urlencode(params) if params else "")


def test_szczegoly_pelna_strona(zalogowany, analiza):
    a = analiza("phishing_klasyczny")
    tresc = zalogowany.get(url(a)).content.decode()
    assert "Zaległa płatność – faktura FV/03/2026" in tresc
    assert "SPF" in tresc
    assert "<iframe sandbox" in tresc
    assert "allow-scripts" not in tresc
    assert "REPLY_TO_INNA_DOMENA" not in tresc  # kody tłumaczone na opisy
    assert "gmail" in tresc


def test_sekcja_htmx_fragment(zalogowany, analiza):
    a = analiza("phishing_klasyczny")
    r = zalogowany.get(url(a, sekcja="ioc"), HTTP_HX_REQUEST="true")
    tresc = r.content.decode()
    assert "<html" not in tresc
    assert "pko-platnosci[.]example" in tresc


def test_ioc_rozbrojone(zalogowany, analiza):
    a = analiza("phishing_klasyczny")
    tresc = zalogowany.get(url(a, sekcja="ioc")).content.decode()
    assert "https://pko-platnosci" not in tresc  # jedyny celowy https:// to link JOE
    assert "hxxps://pko-platnosci[.]example/login" in tresc
    assert "185[.]243[.]115[.]20" in tresc


@pytest.mark.parametrize("sekcja", ["wiadomosc", "naglowki", "received", "zalaczniki", "linki", "ioc"])
def test_wszystkie_sekcje(zalogowany, analiza, sekcja):
    for nazwa in ("phishing_klasyczny", "mail_w_mailu", "zip_aes_haslo_w_tresci", "qr_inline"):
        assert zalogowany.get(url(analiza(nazwa), sekcja=sekcja)).status_code == 200


def test_received_tabela(zalogowany, analiza):
    tresc = zalogowany.get(url(analiza("phishing_klasyczny"), sekcja="received")).content.decode()
    assert "185[.]243[.]115[.]20" in tresc
    assert "2 s" in tresc  # opóźnienie 09:13:58 → 09:14:00


def test_linki_niezgodny(zalogowany, analiza):
    tresc = zalogowany.get(url(analiza("phishing_klasyczny"), sekcja="linki")).content.decode()
    assert "niezgodny" in tresc
    assert "pko.pl" in tresc


def test_podglad_csp(zalogowany, analiza):
    a = analiza("phishing_klasyczny")
    r = zalogowany.get(reverse("analizy:podglad", args=[a.pk, "0"]))
    assert r.status_code == 200
    assert r["Content-Security-Policy"] == CSP
    assert r["X-Frame-Options"] == "SAMEORIGIN"
    assert "Prosimy o płatność" in r.content.decode()


def test_podglad_bez_skryptow(zalogowany, analityk, zbuduj_mail):
    a, _ = utworz_lub_otworz(zbuduj_mail(html="<p>x</p><script>alert(1)</script>"), "s.eml", analityk)
    tresc = zalogowany.get(reverse("analizy:podglad", args=[a.pk, "0"])).content.decode()
    assert "<script" not in tresc


def test_podglad_wymaga_logowania(client, analiza):
    a = analiza("phishing_klasyczny")
    assert client.get(reverse("analizy:podglad", args=[a.pk, "0"])).status_code == 302


def test_mail_bez_tresci_i_naglowkow(zalogowany, analiza):
    a = analiza("tylko_zalacznik_bez_naglowkow_auth")
    assert "brak danych" in zalogowany.get(url(a)).content.decode()
    assert "Wiadomość nie ma treści" in zalogowany.get(url(a)).content.decode()
    assert "Brak nagłówków Received" in zalogowany.get(url(a, sekcja="received")).content.decode()


def test_tekst_bez_html_w_pre(zalogowany, analiza):
    tresc = zalogowany.get(url(analiza("cp1250_bez_charset"))).content.decode()
    assert "<pre" in tresc and "Zażółć gęślą jaźń" in tresc
    assert "<iframe" not in tresc


def test_zagniezdzona_wiadomosc(zalogowany, analiza):
    a = analiza("mail_w_mailu")
    assert "Blokada konta" in zalogowany.get(url(a, wiadomosc="0.1")).content.decode()
    assert zalogowany.get(url(a, wiadomosc="9.9")).status_code == 404
    assert zalogowany.get(reverse("analizy:podglad", args=[a.pk, "9.9"])).status_code == 404


def test_nieznana_sekcja_404(zalogowany, analiza):
    assert zalogowany.get(url(analiza("zip_exe"), sekcja="xyz")).status_code == 404


def test_wymaga_logowania(client, analiza):
    assert client.get(url(analiza("zip_exe"))).status_code == 302


def test_zdarzenie_otwarcia_raz_na_sesje(zalogowany, analiza):
    a = analiza("zip_exe")
    zalogowany.get(url(a))
    zalogowany.get(url(a, sekcja="ioc"))
    assert Zdarzenie.objects.filter(analiza=a, typ="otwarcie").count() == 1


def sekcja_zalacznikow(tresc: str) -> str:
    start = tresc.find('class="zalaczniki-wiadomosci"')
    return tresc[start:tresc.find("</section>", start)] if start >= 0 else ""


def test_zalaczniki_pod_wiadomoscia(zalogowany, analiza):
    s = sekcja_zalacznikow(zalogowany.get(url(analiza("zip_aes_haslo_w_tresci"))).content.decode())
    assert "Załączniki (1)" in s and "faktura.zip" in s and "1 plik w środku" in s


def test_zalaczniki_pod_wiadomoscia_inline_osobno(zalogowany, analiza):
    s = sekcja_zalacznikow(zalogowany.get(url(analiza("qr_inline"))).content.decode())
    assert "qr.png" in s and "w treści" in s


def test_brak_zalacznikow_pod_wiadomoscia(zalogowany, analiza):
    assert sekcja_zalacznikow(zalogowany.get(url(analiza("phishing_klasyczny"))).content.decode()) == ""


def test_zagniezdzona_wiadomosc_jako_zalacznik(zalogowany, analiza):
    s = sekcja_zalacznikow(zalogowany.get(url(analiza("mail_w_mailu"))).content.decode())
    assert "zgloszenie.eml" in s and "wiadomosc=0.1" in s
