import hashlib
import io

import py7zr
import pyzipper
import pytest

from mailcore.archiwa import Budzet, hasla_z_tekstu, jest_archiwum, rozpakuj
from mailcore.model import Limity, zalacznik_z_danych
from mailcore.parsuj import parsuj
from mailcore.tekst import tekst_z_html

EXE = b"MZ\x90\x00" + b"\x00" * 60


def zip_(pliki, haslo=None):
    buf = io.BytesIO()
    kw = {"encryption": pyzipper.WZ_AES} if haslo else {}
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, **kw) as zf:
        if haslo:
            zf.setpassword(haslo.encode())
        for nazwa, dane in pliki:
            zf.writestr(nazwa, dane)
    return buf.getvalue()


def zal(nazwa, dane):
    return zalacznik_z_danych(nazwa, "application/zip", dane)


def kody(lista):
    return [o.kod for o in lista]


def test_hasla_z_tekstu():
    assert hasla_z_tekstu("Hasło do pliku: Faktura2026!") == ["Faktura2026!", "infected"]
    assert "abc123" in hasla_z_tekstu("password=abc123")
    assert hasla_z_tekstu("Hasło: tajne.") == ["tajne", "infected"]
    assert hasla_z_tekstu(None) == ["infected"]


def test_tekst_z_html():
    assert tekst_z_html("<p>Hasło:</p><b>abc</b>").split() == ["Hasło:", "abc"]


def test_jest_archiwum():
    assert jest_archiwum(zal("a.zip", zip_([("a", b"x")])))
    assert jest_archiwum(zal("a.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 20))
    assert not jest_archiwum(zal("a.pdf", b"%PDF-1.4"))


def test_zip_rozpakowany():
    z = zal("faktura.zip", zip_([("faktura.exe", EXE)]))
    assert rozpakuj(z, ["infected"], Budzet(10**6)) == []
    assert z.dzieci[0].nazwa == "faktura.exe"
    assert z.dzieci[0].sha256 == hashlib.sha256(EXE).hexdigest()


def test_zip_aes_haslo_z_tresci(zbuduj_mail):
    dane = zbuduj_mail(
        tekst="W załączniku faktura. Hasło: Faktura2026!",
        zalaczniki=[("faktura.zip", "application/zip", zip_([("faktura.exe", EXE)], "Faktura2026!"))],
    )
    w = parsuj(dane, "a.eml")
    z = w.zalaczniki[0]
    assert z.zaszyfrowany is False
    assert z.dzieci[0].nazwa == "faktura.exe"


def test_haslo_z_html(zbuduj_mail):
    dane = zbuduj_mail(
        tekst=None,
        html="<p>Hasło:</p><p><b>tajne99</b></p>",
        zalaczniki=[("a.zip", "application/zip", zip_([("a.exe", EXE)], "tajne99"))],
    )
    assert parsuj(dane, "a.eml").zalaczniki[0].dzieci


def test_zip_nieznane_haslo():
    z = zal("a.zip", zip_([("a.exe", EXE)], "xyz"))
    ostrz = rozpakuj(z, ["infected"], Budzet(10**6))
    assert z.zaszyfrowany is True
    assert z.dzieci == []
    assert kody(ostrz) == ["ZASZYFROWANE"]


def test_7z():
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as a:
        a.writestr(EXE, "faktura.exe")
    z = zal("a.7z", buf.getvalue())
    assert jest_archiwum(z)
    assert rozpakuj(z, ["infected"], Budzet(10**6)) == []
    assert z.dzieci[0].sha256 == hashlib.sha256(EXE).hexdigest()


def test_7z_z_haslem():
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password="tajne") as a:
        a.writestr(EXE, "faktura.exe")
    z = zal("a.7z", buf.getvalue())
    rozpakuj(z, ["tajne", "infected"], Budzet(10**6))
    assert z.dzieci and z.zaszyfrowany is False


def test_zip_bomba():
    z = zal("bomba.zip", zip_([("zera.bin", b"\x00" * 10 * 1024 * 1024)]))
    ostrz = rozpakuj(z, ["infected"], Budzet(1024 * 1024))
    assert "LIMIT_ROZPAKOWANIE" in kody(ostrz)


def test_budzet_wspolny_dla_calego_pliku(zbuduj_mail):
    duzy = zip_([("zera.bin", b"\x00" * 3 * 1024 * 1024)])
    dane = zbuduj_mail(zalaczniki=[(f"{i}.zip", "application/zip", duzy) for i in range(3)])
    w = parsuj(dane, "a.eml", Limity(max_rozpakowane=5 * 1024 * 1024))
    assert "LIMIT_ROZPAKOWANIE" in kody(w.ostrzezenia)


def test_zip_uszkodzony():
    z = zal("a.zip", b"PK\x03\x04" + b"\x00" * 50)
    assert kody(rozpakuj(z, ["infected"], Budzet(10**6))) == ["ARCHIWUM_USZKODZONE"]


def test_rar_uszkodzony_bez_wyjatku():
    z = zal("a.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 20)
    assert kody(rozpakuj(z, ["infected"], Budzet(10**6)))[0] in ("ARCHIWUM_USZKODZONE", "BRAK_NARZEDZIA")


def test_eml_w_zipie(zbuduj_mail):
    wewn = zbuduj_mail(temat="Wewnętrzny z zipa")
    dane = zbuduj_mail(zalaczniki=[("z.zip", "application/zip", zip_([("zgloszenie.eml", wewn)]))])
    w = parsuj(dane, "a.eml")
    d = w.zalaczniki[0].dzieci[0]
    assert d.wiadomosc is not None
    assert d.wiadomosc.temat == "Wewnętrzny z zipa"
    assert d.wiadomosc.id == "0.1"


def test_zip_w_zipie_limit_glebokosci(zbuduj_mail):
    dane = zip_([("dno.exe", EXE)])
    for i in range(7):
        dane = zip_([(f"poziom{i}.zip", dane)])
    mail = zbuduj_mail(zalaczniki=[("a.zip", "application/zip", dane)])
    w = parsuj(mail, "a.eml", Limity(max_glebokosc=5))
    assert "LIMIT_GLEBOKOSC" in kody(w.ostrzezenia)
