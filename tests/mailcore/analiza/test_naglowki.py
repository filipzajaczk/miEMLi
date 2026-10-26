from mailcore.analiza.podszywanie import wykryj_podszywanie
from mailcore.analiza.received import sciezka_received
from mailcore.analiza.uwierzytelnienie import Uwierzytelnienie, sprawdz_uwierzytelnienie
from mailcore.domeny import domena_bazowa
from mailcore.parsuj import parsuj


def mail(zbuduj_mail, naglowki, od="Nadawca <nadawca@example.com>"):
    return parsuj(zbuduj_mail(od=od, naglowki=naglowki), "a.eml")


def kody(sygnaly):
    return [s.kod for s in sygnaly]


def test_auth_results(zbuduj_mail):
    w = mail(zbuduj_mail, [(
        "Authentication-Results",
        "mx.firma.pl; spf=fail smtp.mailfrom=x.com; dkim=pass header.d=x.com; dmarc=fail",
    )])
    assert sprawdz_uwierzytelnienie(w) == Uwierzytelnienie("fail", "pass", "fail")


def test_auth_tylko_pierwszy_naglowek(zbuduj_mail):
    w = mail(zbuduj_mail, [
        ("Authentication-Results", "mx.firma.pl; spf=pass"),
        ("Authentication-Results", "evil; spf=fail"),
    ])
    assert sprawdz_uwierzytelnienie(w).spf == "pass"


def test_auth_wielkosc_liter(zbuduj_mail):
    w = mail(zbuduj_mail, [("Authentication-Results", "mx; SPF=SoftFail; DKIM=None")])
    assert sprawdz_uwierzytelnienie(w) == Uwierzytelnienie("softfail", "none", None)


def test_auth_brak(zbuduj_mail):
    assert sprawdz_uwierzytelnienie(mail(zbuduj_mail, [])) == Uwierzytelnienie(None, None, None)


def test_received_kolejnosc_i_ip(zbuduj_mail):
    w = mail(zbuduj_mail, [
        ("Received", "from mx1 (mx1 [10.0.0.1]) by mx2; Tue, 24 Oct 2026 09:14:00 +0200"),
        ("Received", "from evil.com (unknown [185.243.115.20]) by mx1; Tue, 24 Oct 2026 09:13:58 +0200"),
    ])
    hopy = sciezka_received(w)
    assert [h.ip for h in hopy] == ["185.243.115.20", "10.0.0.1"]
    assert hopy[0].od == "evil.com"
    assert hopy[0].przez == "mx1"
    assert hopy[0].czas is not None and hopy[0].czas.tzinfo is not None


def test_received_brak_i_smieci(zbuduj_mail):
    assert sciezka_received(mail(zbuduj_mail, [])) == []
    hopy = sciezka_received(mail(zbuduj_mail, [("Received", "garbage")]))
    assert len(hopy) == 1
    assert (hopy[0].od, hopy[0].przez, hopy[0].ip, hopy[0].czas) == (None, None, None, None)


def test_reply_to_inna_domena(zbuduj_mail):
    w = mail(
        zbuduj_mail,
        [("Reply-To", "pko.rozliczenia@gmail.com")],
        od="Księgowość PKO <ksiegowosc@pko-platnosci.com>",
    )
    assert set(kody(wykryj_podszywanie(w))) >= {"REPLY_TO_INNA_DOMENA", "DARMOWA_POCZTA"}


def test_return_path_inna_domena(zbuduj_mail):
    w = mail(zbuduj_mail, [("Return-Path", "<bounce@spam.example>")], od="a@firma.pl")
    assert kody(wykryj_podszywanie(w)) == ["RETURN_PATH_INNA_DOMENA"]


def test_nazwa_z_innym_adresem(zbuduj_mail):
    w = mail(zbuduj_mail, [], od='"bok@pko.pl" <x@evil.com>')
    assert "NAZWA_Z_INNYM_ADRESEM" in kody(wykryj_podszywanie(w))


def test_darmowa_poczta_w_from(zbuduj_mail):
    w = mail(zbuduj_mail, [], od="Bank PKO <x@gmail.com>")
    assert kody(wykryj_podszywanie(w)) == ["DARMOWA_POCZTA"]


def test_czysty_mail_bez_sygnalow(zbuduj_mail):
    w = mail(
        zbuduj_mail,
        [("Reply-To", "jan@FIRMA.pl"), ("Return-Path", "<bounce@mail.firma.pl>")],
        od="Jan Kowalski <jan@firma.pl>",
    )
    assert wykryj_podszywanie(w) == []


def test_brak_from(zbuduj_mail):
    assert wykryj_podszywanie(mail(zbuduj_mail, [], od=None)) == []


def test_domena_bazowa():
    assert domena_bazowa("mail.firma.pl") == "firma.pl"
    assert domena_bazowa("a.b.gov.pl") == "b.gov.pl"
    assert domena_bazowa("x.co.uk") == "x.co.uk"
    assert domena_bazowa("FIRMA.PL.") == "firma.pl"
