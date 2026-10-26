"""Testy z końcowego przeglądu: wrogie wejścia, które psuły lub ukrywały analizę."""

import io
import json

import pyzipper
from PIL import Image

from mailcore.analiza import analizuj
from mailcore.analiza.linki import wyciagnij_linki
from mailcore.analiza.qr import odczytaj_qr
from mailcore.archiwa import MAKS_HASEL, MAKS_POZYCJI, Budzet, hasla_z_tekstu, rozpakuj
from mailcore.model import Limity, zalacznik_z_danych
from mailcore.parsuj import parsuj
from mailcore.serializacja import do_json

EXE = b"MZ\x90\x00" + b"\x00" * 60


def zip_(pliki):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
        for nazwa, dane in pliki:
            zf.writestr(nazwa, dane)
    return buf.getvalue()


def kody(lista):
    return [o.kod for o in lista]


# --- NUL w treści (Postgres odrzuca \u0000) ---

def test_nul_usuniety_z_json():
    dane = (b"From: a@x.pl\r\nSubject: a\x00b\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\naGkAdGhlcmU=\r\n")
    w = parsuj(dane, "a.eml")
    assert "\x00" not in json.dumps(do_json(w, analizuj(w))).replace("\\u0000", "\x00")


# --- bomba nie kasuje wyników, budżet liczy tylko przeczytane bajty ---

def test_bomba_zachowuje_wczesniejsze_pliki():
    z = zalacznik_z_danych("a.zip", "application/zip",
                           zip_([("faktura.exe", EXE), ("bomba.bin", b"\x00" * 5 * 1024 * 1024)]))
    ostrz = rozpakuj(z, ["infected"], Budzet(1024 * 1024))
    assert "LIMIT_ROZPAKOWANIE" in kody(ostrz)
    assert [d.nazwa for d in z.dzieci] == ["faktura.exe"]


def test_po_bombie_male_archiwum_dalej_rozpakowane():
    budzet = Budzet(1024 * 1024)
    bomba = zalacznik_z_danych("b.zip", "application/zip", zip_([("zera", b"\x00" * 5 * 1024 * 1024)]))
    male = zalacznik_z_danych("m.zip", "application/zip", zip_([("faktura.exe", EXE)]))
    rozpakuj(bomba, ["infected"], budzet)
    assert rozpakuj(male, ["infected"], budzet) == []
    assert male.dzieci[0].nazwa == "faktura.exe"


# --- limity liczności ---

def test_limit_pozycji_archiwum():
    z = zalacznik_z_danych("a.zip", "application/zip", zip_([(f"{i}.txt", b"") for i in range(MAKS_POZYCJI + 50)]))
    ostrz = rozpakuj(z, ["infected"], Budzet(10**8))
    assert len(z.dzieci) == MAKS_POZYCJI
    assert "LIMIT_ROZPAKOWANIE" in kody(ostrz)


def test_limit_hasel():
    tekst = "\n".join(f"haslo: p{i}" for i in range(500))
    hasla = hasla_z_tekstu(tekst)
    assert len(hasla) == MAKS_HASEL + 1
    assert hasla[-1] == "infected"


def test_limit_linkow(zbuduj_mail):
    from mailcore.analiza.linki import MAKS_LINKOW

    tekst = " ".join(f"https://e{i}.example/" for i in range(MAKS_LINKOW + 100))
    assert len(wyciagnij_linki(parsuj(zbuduj_mail(tekst=tekst), "a.eml"))) == MAKS_LINKOW


def test_limit_zalacznikow(zbuduj_mail):
    from mailcore.eml import MAKS_ZALACZNIKOW

    w = parsuj(zbuduj_mail(zalaczniki=[(f"{i}.bin", "application/octet-stream", b"x")
                                       for i in range(MAKS_ZALACZNIKOW + 20)]), "a.eml")
    assert len(w.zalaczniki) == MAKS_ZALACZNIKOW
    assert "LIMIT_ROZPAKOWANIE" in kody(w.ostrzezenia)


# --- QR: limit pikseli i liczby obrazów ---

def test_qr_ogromny_obraz_pominiety():
    buf = io.BytesIO()
    Image.new("1", (6000, 4000), 1).save(buf, "PNG")
    assert odczytaj_qr(buf.getvalue()) == []


def test_qr_limit_obrazow(zbuduj_mail):
    import segno

    from mailcore.analiza.ioc import MAKS_OBRAZOW_QR

    obrazy = []
    for i in range(MAKS_OBRAZOW_QR + 5):
        buf = io.BytesIO()
        segno.make(f"https://e{i}.example/qr", error="m").save(buf, kind="png", scale=4, border=4)
        obrazy.append((f"{i}.png", "image/png", buf.getvalue()))
    wynik = analizuj(parsuj(zbuduj_mail(zalaczniki=obrazy), "a.eml"))
    assert len([i for i in wynik.ioc if i.zrodlo == "qr" and i.typ == "url"]) == MAKS_OBRAZOW_QR


# --- głęboki MIME, ostrzeżenie o głębokości, encoded-word ---

def test_gleboki_mime_bez_wyjatku():
    gora, dol = b"", b""
    for i in range(1200):
        gora += f'Content-Type: multipart/mixed; boundary="b{i}"\r\n\r\n--b{i}\r\n'.encode()
        dol = f"\r\n--b{i}--\r\n".encode() + dol
    dane = b"From: a@x.pl\r\nSubject: gleboki\r\nMIME-Version: 1.0\r\n" + gora + b"Content-Type: text/plain\r\n\r\nx" + dol
    w = parsuj(dane, "a.eml")
    assert w.temat == "gleboki"
    assert "USZKODZONA_WIADOMOSC" in kody(w.ostrzezenia)


def test_limit_glebokosci_widoczny_na_glownej(zbuduj_mail):
    dane = zbuduj_mail(temat="dno")
    for i in range(7):
        dane = zbuduj_mail(temat=f"p{i}", zagniezdzone=[dane])
    w = parsuj(dane, "a.eml", Limity(max_glebokosc=5))
    assert "LIMIT_GLEBOKOSC" in kody(w.ostrzezenia)


def test_niepoprawny_encoded_word_ostrzezenie():
    w = parsuj(b"From: a@x.pl\r\nSubject: =?utf-8?b?!!!?= =?x-unknown?q?abc?=\r\n\r\nx\r\n", "a.eml")
    assert "NAGLOWEK" in kody(w.ostrzezenia)
