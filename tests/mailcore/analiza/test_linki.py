from mailcore.analiza.linki import rozpakuj_przekierowanie, wyciagnij_linki
from mailcore.parsuj import parsuj


def linki(zbuduj_mail, **kw):
    return wyciagnij_linki(parsuj(zbuduj_mail(**kw), "a.eml"))


def test_safelinks():
    url = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Flogin&data=05"
    assert rozpakuj_przekierowanie(url) == "https://evil.com/login"


def test_proofpoint_v2():
    url = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.com_login&d=DwMF"
    assert rozpakuj_przekierowanie(url) == "https://evil.com/login"


def test_proofpoint_v3():
    url = "https://urldefense.com/v3/__https://evil.com/login__;!!ABC!xyz$"
    assert rozpakuj_przekierowanie(url) == "https://evil.com/login"


def test_proofpoint_v3_zakodowane_znaki():
    # "?" i "=" zastąpione "*", ich bajty w base64url ("Pz0") po "__;"
    url = "https://urldefense.com/v3/__https://evil.com/a*b*1__;Pz0!!ABC!xyz$"
    assert rozpakuj_przekierowanie(url) == "https://evil.com/a?b=1"


def test_zwykly_url_bez_przekierowania():
    assert rozpakuj_przekierowanie("https://pko.pl/") is None


def test_niezgodny_tekst(zbuduj_mail):
    wynik = linki(zbuduj_mail, html='<a href="https://evil.com/x">pko.pl</a>')
    assert len(wynik) == 1
    assert wynik[0].niezgodny is True
    assert wynik[0].tekst == "pko.pl"
    assert wynik[0].zrodlo == "html"


def test_zgodny_tekst(zbuduj_mail):
    assert linki(zbuduj_mail, html='<a href="https://www.pko.pl/x">pko.pl</a>')[0].niezgodny is False
    assert linki(zbuduj_mail, html='<a href="https://evil.com">Kliknij tutaj</a>')[0].niezgodny is False


def test_url_z_tekstu(zbuduj_mail):
    wynik = linki(zbuduj_mail, tekst="Wejdź na https://evil.com/fv?id=1.")
    assert [(l.url, l.zrodlo) for l in wynik] == [("https://evil.com/fv?id=1", "tekst")]


def test_niezgodnosc_po_rozpakowaniu(zbuduj_mail):
    href = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Flogin&amp;data=05"
    wynik = linki(zbuduj_mail, html=f'<a href="{href}">pko.pl</a>')
    assert wynik[0].docelowy == "https://evil.com/login"
    assert wynik[0].niezgodny is True


def test_bez_duplikatow_html_i_tekst(zbuduj_mail):
    wynik = linki(
        zbuduj_mail,
        tekst="Faktura: https://evil.com/fv",
        html='<a href="https://evil.com/fv">https://evil.com/fv</a>',
    )
    assert [l.url for l in wynik] == ["https://evil.com/fv"]


def test_pomija_mailto_i_kotwice(zbuduj_mail):
    wynik = linki(zbuduj_mail, html='<a href="mailto:a@b.pl">a</a><a href="#top">x</a><a href="javascript:x()">y</a>')
    assert wynik == []
