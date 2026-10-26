import hashlib

from mailcore.parsuj import parsuj


def kody(w):
    return [o.kod for o in w.ostrzezenia]


def test_podstawowe_pola(zbuduj_mail):
    dane = zbuduj_mail(
        temat="Zaległa płatność",
        od="Księgowość <a@x.pl>",
        tekst="Dzień dobry",
        html="<p>Dzień dobry</p>",
    )
    w = parsuj(dane, "a.eml")
    assert w.temat == "Zaległa płatność"
    assert "a@x.pl" in w.od
    assert w.tekst and "Dzień dobry" in w.tekst
    assert w.html and "<p>" in w.html
    assert w.id == "0"
    assert w.ostrzezenia == []


def test_temat_encoded_word():
    dane = b"From: a@x.pl\r\nSubject: =?utf-8?B?WmHFvMOzxYLEhw==?=\r\n\r\ntresc\r\n"
    w = parsuj(dane, "a.eml")
    assert w.temat == "Zażółć"


def test_cp1250_bez_charset():
    dane = (
        b"From: a@x.pl\r\nSubject: t\r\nContent-Type: text/plain\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\n"
        + "Zażółć gęślą jaźń".encode("cp1250")
        + b"\r\n"
    )
    w = parsuj(dane, "a.eml")
    assert "Zażółć gęślą jaźń" in w.tekst
    assert kody(w) == ["KODOWANIE"]


def test_zepsuty_naglowek():
    dane = b"From: a@x.pl\r\nSubject: =?utf-8?B?!!!niepoprawne?=\r\n\r\ntresc\r\n"
    w = parsuj(dane, "a.eml")
    assert w.temat
    assert "NAGLOWEK" in kody(w)


def test_zalacznik_hashe(zbuduj_mail):
    dane = zbuduj_mail(zalaczniki=[("faktura.pdf", "application/pdf", b"%PDF-1.4 test")])
    w = parsuj(dane, "a.eml")
    z = w.zalaczniki[0]
    assert z.nazwa == "faktura.pdf"
    assert z.sha256 == hashlib.sha256(b"%PDF-1.4 test").hexdigest()
    assert z.md5 == hashlib.md5(b"%PDF-1.4 test").hexdigest()
    assert z.rozmiar == 13
    assert z.typ_mime == "application/pdf"


def test_inline_cid(zbuduj_mail):
    dane = zbuduj_mail(
        html='<img src="cid:logo1">',
        zalaczniki=[("logo.png", "image/png", b"\x89PNG\r\n\x1a\nxx", {"cid": "logo1", "inline": True})],
    )
    w = parsuj(dane, "a.eml")
    z = w.zalaczniki[0]
    assert z.content_id == "logo1"
    assert z.inline is True


def test_mail_bez_tresci(zbuduj_mail):
    dane = zbuduj_mail(tekst=None, zalaczniki=[("a.bin", "application/octet-stream", b"x")])
    w = parsuj(dane, "a.eml")
    assert w.tekst is None and w.html is None
    assert len(w.zalaczniki) == 1
