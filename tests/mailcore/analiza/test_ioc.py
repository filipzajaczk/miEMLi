import io

import pyzipper
import segno

from mailcore.analiza import analizuj
from mailcore.parsuj import parsuj

EXE = b"MZ\x90\x00" + b"\x00" * 60


def ioc(zbuduj_mail, ignorowane=frozenset(), **kw):
    return analizuj(parsuj(zbuduj_mail(**kw), "a.eml"), ignorowane).ioc


def po_wartosci(lista):
    return {(i.typ, i.wartosc): i for i in lista}


def zip_(pliki):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w") as zf:
        for nazwa, dane in pliki:
            zf.writestr(nazwa, dane)
    return buf.getvalue()


def test_drzewo_zip_exe(zbuduj_mail):
    lista = ioc(zbuduj_mail, zalaczniki=[("faktura.zip", "application/zip", zip_([("faktura.exe", EXE)]))])
    pliki = {i.etykieta: i for i in lista if i.typ == "plik"}
    assert pliki["faktura.exe"].rodzic_id == pliki["faktura.zip"].id
    assert pliki["faktura.zip"].rodzic_id is None
    assert pliki["faktura.exe"].zrodlo == "zalacznik"
    assert set(pliki["faktura.exe"].hashe) == {"md5", "sha1", "sha256"}
    assert pliki["faktura.exe"].wartosc == pliki["faktura.exe"].hashe["sha256"]


def test_url_i_domena(zbuduj_mail):
    m = po_wartosci(ioc(zbuduj_mail, tekst="Zaloguj: https://evil.com/login"))
    url = m[("url", "https://evil.com/login")]
    assert m[("domena", "evil.com")].rodzic_id == url.id
    assert url.zrodlo == "tresc"


def test_url_z_ip(zbuduj_mail):
    m = po_wartosci(ioc(zbuduj_mail, tekst="http://185.243.115.20/x"))
    assert m[("ip", "185.243.115.20")].rodzic_id == m[("url", "http://185.243.115.20/x")].id


def test_email_nadawcy_bez_odbiorcow(zbuduj_mail):
    m = po_wartosci(ioc(zbuduj_mail, od="Zły <A@Evil.com>", do="jan@firma.pl", tekst="x"))
    assert ("email", "a@evil.com") in m
    assert m[("domena", "evil.com")].rodzic_id == m[("email", "a@evil.com")].id
    assert ("email", "jan@firma.pl") not in m


def test_ip_prywatne_pominiete(zbuduj_mail):
    lista = ioc(zbuduj_mail, naglowki=[
        ("Received", "from mx1 (mx1 [10.0.0.1]) by mx2; Tue, 24 Oct 2026 09:14:00 +0200"),
        ("Received", "from evil (unknown [185.243.115.20]) by mx1; Tue, 24 Oct 2026 09:13:58 +0200"),
    ])
    ips = [i for i in lista if i.typ == "ip"]
    assert [(i.wartosc, i.zrodlo) for i in ips] == [("185.243.115.20", "naglowek")]


def test_ip_z_tresci(zbuduj_mail):
    lista = ioc(zbuduj_mail, tekst="Serwer 185.243.115.21 oraz 192.168.1.1")
    assert [i.wartosc for i in lista if i.typ == "ip"] == ["185.243.115.21"]


def test_ignorowane_domeny(zbuduj_mail):
    lista = ioc(
        zbuduj_mail,
        ignorowane=frozenset({"firma.pl"}),
        od="it@firma.pl",
        tekst="https://intranet.firma.pl/x i https://evil.com/",
    )
    wartosci = {i.wartosc for i in lista}
    assert not any("firma.pl" in v for v in wartosci)
    assert "https://evil.com/" in wartosci


def test_deduplikacja(zbuduj_mail):
    lista = ioc(zbuduj_mail, tekst="https://evil.com/a https://evil.com/b")
    assert [i.wartosc for i in lista if i.typ == "domena"].count("evil.com") == 1
    assert len({i.id for i in lista}) == len(lista)


def test_ioc_zagniezdzonego_maila(zbuduj_mail):
    wewn = zbuduj_mail(temat="W", tekst="https://evil.com/wewn")
    lista = ioc(zbuduj_mail, tekst="Przekazuję", zagniezdzone=[wewn])
    m = po_wartosci(lista)
    plik = next(i for i in lista if i.typ == "plik")
    assert m[("url", "https://evil.com/wewn")].rodzic_id == plik.id


def test_url_po_rozpakowaniu_safelinks(zbuduj_mail):
    href = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Flogin&data=05"
    m = po_wartosci(ioc(zbuduj_mail, html=f'<a href="{href}">pko.pl</a>'))
    assert m[("url", "https://evil.com/login")].etykieta == "pko.pl"


def test_qr_jako_url(zbuduj_mail):
    buf = io.BytesIO()
    segno.make("https://evil.com/qr", error="m").save(buf, kind="png", scale=6, border=4)
    lista = ioc(
        zbuduj_mail,
        html='<img src="cid:qr1">',
        zalaczniki=[("qr.png", "image/png", buf.getvalue(), {"cid": "qr1", "inline": True})],
    )
    m = po_wartosci(lista)
    url = m[("url", "https://evil.com/qr")]
    assert url.zrodlo == "qr"
    obraz = next(i for i in lista if i.typ == "plik")
    assert url.rodzic_id == obraz.id


def test_analiza_per_wiadomosc(zbuduj_mail):
    wewn = zbuduj_mail(temat="W")
    wynik = analizuj(parsuj(zbuduj_mail(zagniezdzone=[wewn]), "a.eml"))
    assert set(wynik.wiadomosci) == {"0", "0.1"}
