"""Parser .eml — jeden poziom. Zagnieżdżone wiadomości zostają bajtami w Zalacznik.dane."""

import email
import email.header
import email.parser
import email.policy
import email.utils
from email.message import EmailMessage

from .model import Ostrzezenie, Wiadomosc, Zalacznik, zalacznik_z_danych

TYP_EML = "message/rfc822"
MAKS_ZALACZNIKOW = 1000


def dekoduj_tekst(dane: bytes, charset: str | None, ostrzezenia: list[Ostrzezenie]) -> str:
    """Zadeklarowany charset → utf-8 → windows-1250 → latin-1 (z ostrzeżeniem przy zgadywaniu)."""
    if charset:
        try:
            return dane.decode(charset)
        except (LookupError, UnicodeDecodeError):
            pass
    else:
        try:
            return dane.decode("utf-8")
        except UnicodeDecodeError:
            pass
    for zapasowe in ("windows-1250", "latin-1"):
        try:
            tekst = dane.decode(zapasowe)
        except UnicodeDecodeError:
            continue
        ostrzezenia.append(
            Ostrzezenie(
                "KODOWANIE",
                f"Nie udało się odczytać treści jako {charset or 'utf-8'}, użyto {zapasowe}.",
            )
        )
        return tekst
    raise AssertionError("latin-1 dekoduje każdy bajt")


def _naglowki(msg: EmailMessage, ostrzezenia: list[Ostrzezenie]) -> list[tuple[str, str]]:
    wynik = []
    for nazwa, surowa in msg.raw_items():
        try:
            h = msg.policy.header_fetch_parse(nazwa, surowa)
            wartosc = str(h)
            if getattr(h, "defects", None) or "\ufffd" in wartosc or not _encoded_words_poprawne(surowa):
                ostrzezenia.append(Ostrzezenie("NAGLOWEK", f"Nagłówek {nazwa} jest nieprawidłowy."))
        except Exception:
            wartosc = str(surowa)
            ostrzezenia.append(Ostrzezenie("NAGLOWEK", f"Nie udało się zdekodować nagłówka {nazwa}."))
        wynik.append((nazwa, " ".join(wartosc.split())))
    return wynik


def _encoded_words_poprawne(surowa) -> bool:
    """Python po cichu pomija błędne =?...?= — sprawdzamy je ściśle."""
    surowa = str(surowa)
    if "=?" not in surowa:
        return True
    try:
        for bajty, charset in email.header.decode_header(surowa):
            if charset and isinstance(bajty, bytes):
                bajty.decode(charset)
    except Exception:
        return False
    return True


def _nazwa_pliku(czesc: EmailMessage, numer: int) -> str | None:
    try:
        return czesc.get_filename()
    except Exception:
        return f"zalacznik_{numer}"


def _czy_zalacznik(czesc: EmailMessage) -> bool:
    if czesc.get_content_type() == TYP_EML:
        return True
    if czesc.get_content_disposition() == "attachment":
        return True
    if czesc.get_content_maintype() != "text":
        return True
    try:
        return czesc.get_filename() is not None
    except Exception:
        return True


def _liscie(czesc: EmailMessage):
    """Części-liście, bez wchodzenia do message/rfc822."""
    if czesc.get_content_type() == TYP_EML:
        yield czesc
    elif czesc.is_multipart():
        for pod in czesc.iter_parts():
            yield from _liscie(pod)
    else:
        yield czesc


def _zalacznik(czesc: EmailMessage, numer: int) -> Zalacznik:
    typ = czesc.get_content_type()
    if typ == TYP_EML:
        wewn = czesc.get_payload(0)
        dane = wewn.as_bytes(policy=email.policy.default)
        nazwa = _nazwa_pliku(czesc, numer) or f"wiadomosc_{numer}.eml"
    else:
        dane = czesc.get_payload(decode=True) or b""
        nazwa = _nazwa_pliku(czesc, numer) or f"zalacznik_{numer}"
    cid = czesc.get("Content-ID")
    return zalacznik_z_danych(
        nazwa,
        typ,
        dane,
        content_id=str(cid).strip().strip("<>") if cid else None,
        inline=czesc.get_content_disposition() == "inline",
    )


def _tylko_naglowki(dane: bytes, id: str) -> Wiadomosc:
    """Awaryjnie, gdy struktura MIME jest zbyt głęboka dla parsera: same nagłówki."""
    ostrzezenia = [
        Ostrzezenie("USZKODZONA_WIADOMOSC", "Struktura MIME jest zbyt głęboka — pokazano tylko nagłówki.")
    ]
    sekcja = dane.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    msg = email.parser.BytesHeaderParser(policy=email.policy.default).parsebytes(sekcja)
    w = Wiadomosc(id, _naglowki(msg, ostrzezenia), None, None, [], None, None, None, [], ostrzezenia)
    uzupelnij_pola(w)
    return w


def parsuj_eml(dane: bytes, id: str) -> Wiadomosc:
    try:
        return _parsuj_eml(dane, id)
    except RecursionError:
        return _tylko_naglowki(dane, id)


def _parsuj_eml(dane: bytes, id: str) -> Wiadomosc:
    msg = email.message_from_bytes(dane, policy=email.policy.default)
    ostrzezenia: list[Ostrzezenie] = []
    naglowki = _naglowki(msg, ostrzezenia)

    tekst = html = None
    zalaczniki: list[Zalacznik] = []
    for numer, czesc in enumerate(_liscie(msg), start=1):
        if len(zalaczniki) >= MAKS_ZALACZNIKOW:
            ostrzezenia.append(
                Ostrzezenie("LIMIT_ROZPAKOWANIE", f"Wiadomość ma ponad {MAKS_ZALACZNIKOW} części — pokazano pierwsze.")
            )
            break
        if _czy_zalacznik(czesc):
            zalaczniki.append(_zalacznik(czesc, numer))
            continue
        surowe = czesc.get_payload(decode=True) or b""
        if czesc.get_content_subtype() == "html" and html is None:
            html = dekoduj_tekst(surowe, czesc.get_content_charset(), ostrzezenia)
        elif czesc.get_content_subtype() != "html" and tekst is None:
            tekst = dekoduj_tekst(surowe, czesc.get_content_charset(), ostrzezenia)

    w = Wiadomosc(
        id=id,
        naglowki=naglowki,
        temat=None,
        od=None,
        do=[],
        data=None,
        tekst=tekst,
        html=html,
        zalaczniki=zalaczniki,
        ostrzezenia=ostrzezenia,
    )
    uzupelnij_pola(w)
    return w


def uzupelnij_pola(w: Wiadomosc) -> None:
    """Temat, od, do i data wyliczone z listy nagłówków (wspólne dla eml i msg)."""
    w.temat = w.naglowek("Subject")
    w.od = w.naglowek("From")
    w.do = [
        adres for _, adres in email.utils.getaddresses(w.naglowki_wszystkie("To")) if adres
    ]
    data = w.naglowek("Date")
    if data:
        try:
            w.data = email.utils.parsedate_to_datetime(data)
        except (TypeError, ValueError):
            w.ostrzezenia.append(Ostrzezenie("NAGLOWEK", "Nieprawidłowa data w nagłówku Date."))
