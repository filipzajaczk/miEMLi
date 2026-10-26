"""Parser .msg (Outlook) — jeden poziom. Osadzone .msg zostają bajtami w Zalacznik.dane."""

import email.policy
import email.utils
import mimetypes
import re
from email.parser import HeaderParser

import extract_msg
from extract_msg.attachments import EmbeddedMsgAttachment

from .eml import _naglowki, dekoduj_tekst, uzupelnij_pola
from .model import NieobslugiwanyPlik, Ostrzezenie, Wiadomosc, Zalacznik, zalacznik_z_danych

TYP_MSG = "application/vnd.ms-outlook"
_META_CHARSET = re.compile(rb"""<meta[^>]+charset=["']?([\w-]+)""", re.IGNORECASE)


def _naglowki_mapi(m) -> list[tuple[str, str]]:
    pary = [
        ("From", m.sender),
        ("To", m.to),
        ("Cc", m.cc),
        ("Subject", m.subject),
        ("Date", email.utils.format_datetime(m.date) if m.date else None),
    ]
    return [(k, " ".join(str(v).split())) for k, v in pary if v]


def _html(m, ostrzezenia: list[Ostrzezenie]) -> str | None:
    try:
        surowe = m.htmlBody
    except Exception:
        return None
    if not surowe:
        return None
    if isinstance(surowe, str):
        return surowe
    znaleziony = _META_CHARSET.search(surowe[:20000])
    charset = znaleziony.group(1).decode("ascii") if znaleziony else None
    return dekoduj_tekst(surowe, charset, ostrzezenia)


def _zalaczniki(m) -> list[Zalacznik]:
    wynik = []
    for numer, a in enumerate(m.attachments, start=1):
        if isinstance(a, EmbeddedMsgAttachment):
            dane = a.data.exportBytes(allowBadEmbed=True)
            nazwa = a.longFilename or a.shortFilename or f"wiadomosc_{numer}.msg"
            if not nazwa.lower().endswith(".msg"):
                nazwa += ".msg"
            typ = TYP_MSG
        else:
            dane = a.data if isinstance(a.data, bytes) else b""
            nazwa = a.longFilename or a.shortFilename or a.displayName or f"zalacznik_{numer}"
            typ = a.mimetype or mimetypes.guess_type(nazwa)[0] or "application/octet-stream"
        cid = a.contentId or a.cid
        wynik.append(
            zalacznik_z_danych(
                nazwa,
                typ,
                dane,
                content_id=cid.strip("<>") if cid else None,
                inline=bool(cid) and bool(getattr(a, "hidden", False)),
            )
        )
    return wynik


def parsuj_msg(dane: bytes, id: str) -> Wiadomosc:
    try:
        m = extract_msg.openMsg(dane)
    except Exception as e:
        raise NieobslugiwanyPlik("Plik nie jest prawidłową wiadomością .msg.") from e
    try:
        ostrzezenia: list[Ostrzezenie] = []
        tekst_naglowkow = getattr(m, "headerText", None)
        if tekst_naglowkow:
            naglowki = _naglowki(
                HeaderParser(policy=email.policy.default).parsestr(tekst_naglowkow), ostrzezenia
            )
        else:
            naglowki = _naglowki_mapi(m)
            ostrzezenia.append(
                Ostrzezenie(
                    "MSG_BEZ_NAGLOWKOW",
                    "Plik .msg nie zawiera nagłówków transportowych (brak SPF/DKIM/Received).",
                )
            )
        w = Wiadomosc(
            id=id,
            naglowki=naglowki,
            temat=None,
            od=None,
            do=[],
            data=None,
            tekst=m.body or None,
            html=_html(m, ostrzezenia),
            zalaczniki=_zalaczniki(m),
            ostrzezenia=ostrzezenia,
        )
        uzupelnij_pola(w)
        return w
    finally:
        m.close()
