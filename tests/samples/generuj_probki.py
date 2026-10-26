"""Generuje syntetyczne próbki .eml i ich oczekiwane wyniki (.expected.json).

Oczekiwania wynikają z tego, jak próbka jest zbudowana — skrypt NIE uruchamia analizatora.
Domeny są fikcyjne (.example). Uruchomienie: python tests/samples/generuj_probki.py
"""

import io
import json
import zipfile
from email import message_from_bytes, policy
from email.message import EmailMessage
from pathlib import Path

import pyzipper
import segno

KATALOG = Path(__file__).resolve().parent
EXE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"PE\x00\x00"
DATA = "Tue, 24 Oct 2026 09:14:00 +0200"


def mail(od, temat, tekst=None, html=None, naglowki=()):
    m = EmailMessage()
    for k, v in naglowki:
        m[k] = v
    m["From"] = od
    m["To"] = "jan.kowalski@firma.example"
    m["Subject"] = temat
    m["Date"] = DATA
    m["Message-ID"] = f"<{abs(hash(temat)) % 10**8}@generator.example>"
    if tekst is not None:
        m.set_content(tekst)
    if html is not None:
        if tekst is None:
            m.set_content(html, subtype="html")
        else:
            m.add_alternative(html, subtype="html")
    return m


def zalacz(m, nazwa, typ, dane, **kw):
    if m.get_content_maintype() != "multipart":
        m.make_mixed()
    maintype, subtype = typ.split("/")
    m.add_attachment(dane, maintype=maintype, subtype=subtype, filename=nazwa, **kw)


def zip_zwykly(nazwa, dane):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo(nazwa, date_time=(2026, 10, 24, 9, 0, 0)), dane)
    return buf.getvalue()


def zip_aes(nazwa, dane, haslo):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(haslo.encode())
        zf.writestr(nazwa, dane)
    return buf.getvalue()


def nadawca(adres):
    return [["email", adres], ["domena", adres.split("@")[1]]]


def zapisz(nazwa, dane: bytes, oczekiwane: dict):
    (KATALOG / f"{nazwa}.eml").write_bytes(dane)
    (KATALOG / f"{nazwa}.expected.json").write_text(
        json.dumps(oczekiwane, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def phishing_klasyczny():
    m = mail(
        '"Księgowość PKO" <ksiegowosc@pko-platnosci.example>',
        "Zaległa płatność – faktura FV/03/2026",
        tekst="Prosimy o płatność. Szczegóły: https://pko-platnosci.example/fv",
        html='<p>Prosimy o płatność.</p><p><a href="https://pko-platnosci.example/login">pko.pl</a></p>',
        naglowki=[
            ("Received", f"from mx1.firma.example (mx1.firma.example [10.0.0.5]) by mx2.firma.example; {DATA}"),
            ("Received", "from pko-platnosci.example (unknown [185.243.115.20]) by mx1.firma.example; "
                         "Tue, 24 Oct 2026 09:13:58 +0200"),
            ("Authentication-Results", "mx.firma.example; spf=fail smtp.mailfrom=pko-platnosci.example; "
                                       "dkim=none; dmarc=fail"),
            ("Reply-To", "pko.rozliczenia@gmail.com"),
        ],
    )
    zapisz("phishing_klasyczny", m.as_bytes(), {
        "ioc": nadawca("ksiegowosc@pko-platnosci.example") + nadawca("pko.rozliczenia@gmail.com") + [
            ["ip", "185.243.115.20"],
            ["url", "https://pko-platnosci.example/login"],
            ["url", "https://pko-platnosci.example/fv"],
        ],
        "uwierzytelnienie": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "sygnaly": ["REPLY_TO_INNA_DOMENA", "DARMOWA_POCZTA"],
        "ostrzezenia": [],
    })


def zip_exe():
    m = mail("Faktury <faktury@evil.example>", "Faktura", tekst="W załączniku faktura.")
    zalacz(m, "faktura.zip", "application/zip", zip_zwykly("faktura.exe", EXE))
    zapisz("zip_exe", m.as_bytes(), {
        "ioc": nadawca("faktury@evil.example") + [["plik", "faktura.zip"], ["plik", "faktura.exe"]],
        "ostrzezenia": [],
    })


def zip_aes_haslo_w_tresci():
    m = mail("Faktury <faktury@evil.example>", "Faktura zabezpieczona",
             tekst="W załączniku faktura.\nHasło do archiwum: Faktura2026!")
    zalacz(m, "faktura.zip", "application/zip", zip_aes("faktura.exe", EXE, "Faktura2026!"))
    zapisz("zip_aes_haslo_w_tresci", m.as_bytes(), {
        "ioc": nadawca("faktury@evil.example") + [["plik", "faktura.zip"], ["plik", "faktura.exe"]],
        "ostrzezenia": [],
    })


def mail_w_mailu():
    wewn = mail("Bank <oszust@evil.example>", "Blokada konta", tekst="Odblokuj: https://evil.example/login")
    m = mail("Jan Partner <jan@partner.example>", "Fwd: Blokada konta", tekst="Przesyłam podejrzaną wiadomość.")
    m.make_mixed()
    m.add_attachment(message_from_bytes(wewn.as_bytes(), policy=policy.default), filename="zgloszenie.eml")
    zapisz("mail_w_mailu", m.as_bytes(), {
        "ioc": nadawca("jan@partner.example") + [["plik", "zgloszenie.eml"]]
               + nadawca("oszust@evil.example") + [["url", "https://evil.example/login"]],
        "ostrzezenia": [],
    })


def safelinks():
    href = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin"
            "&amp;data=05%7C01&amp;reserved=0")
    m = mail("IT <it@evil.example>", "Hasło wygasa", html=f'<p>Hasło wygasa.</p><a href="{href}">Zaloguj się</a>')
    zapisz("safelinks", m.as_bytes(), {
        "ioc": nadawca("it@evil.example") + [["url", "https://evil.example/login"]],
        "ostrzezenia": [],
    })


def qr_inline():
    buf = io.BytesIO()
    segno.make("https://evil.example/qr", error="m").save(buf, kind="png", scale=6, border=4)
    m = mail("Kadry <kadry@evil.example>", "Zeskanuj kod", tekst="Zeskanuj kod",
             html='<p>Zeskanuj kod:</p><img src="cid:qr1">')
    m.get_payload()[1].add_related(buf.getvalue(), maintype="image", subtype="png", cid="<qr1>",
                                   filename="qr.png", disposition="inline")
    zapisz("qr_inline", m.as_bytes(), {
        "ioc": nadawca("kadry@evil.example") + [["plik", "qr.png"], ["url", "https://evil.example/qr"]],
        "ostrzezenia": [],
    })


def cp1250_bez_charset():
    dane = (
        b"From: Nadawca <nadawca@nadawca.example>\r\nTo: jan.kowalski@firma.example\r\n"
        b"Subject: Kodowanie\r\nDate: " + DATA.encode() + b"\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        + "Zażółć gęślą jaźń".encode("cp1250") + b"\r\n"
    )
    zapisz("cp1250_bez_charset", dane, {
        "ioc": nadawca("nadawca@nadawca.example"),
        "ostrzezenia": ["KODOWANIE"],
    })


def tylko_zalacznik_bez_naglowkow_auth():
    m = mail("Biuro <biuro@nadawca.example>", "Dokument")
    zalacz(m, "dokument.pdf", "application/pdf", b"%PDF-1.4\n%test\n")
    zapisz("tylko_zalacznik_bez_naglowkow_auth", m.as_bytes(), {
        "ioc": nadawca("biuro@nadawca.example") + [["plik", "dokument.pdf"]],
        "uwierzytelnienie": {"spf": None, "dkim": None, "dmarc": None},
        "sygnaly": [],
        "ostrzezenia": [],
    })


if __name__ == "__main__":
    for f in (phishing_klasyczny, zip_exe, zip_aes_haslo_w_tresci, mail_w_mailu, safelinks, qr_inline,
              cp1250_bez_charset, tylko_zalacznik_bez_naglowkow_auth):
        f()
        print("zapisano", f.__name__)
