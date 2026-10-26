"""Rozpakowywanie archiwów zip/7z/rar w pamięci, z hasłami i wspólnym budżetem bajtów."""

import io
import mimetypes
import re
import zipfile

import py7zr
import py7zr.exceptions
import pyzipper
import rarfile
from py7zr.io import Py7zIO, WriterFactory

from .model import Ostrzezenie, Zalacznik, zalacznik_z_danych

HASLO_DOMYSLNE = "infected"
# "Hasło: X", "hasło do archiwum: X", "password=X" — do 3 słów między słowem kluczowym a separatorem
_HASLO = re.compile(
    r"\b(?:hasło|haslo|password|passwd|pass|pwd|kod)(?:\s+[^\s:=]+){0,3}?\s*[:=]\s*(\S+)",
    re.IGNORECASE,
)
_KAWALEK = 64 * 1024
MAKS_POZYCJI = 1000  # plików z jednego archiwum
MAKS_HASEL = 20  # prób haseł z treści (plus "infected")

MAGIC_ZIP = b"PK\x03\x04"
MAGIC_7Z = b"7z\xbc\xaf\x27\x1c"
MAGIC_RAR = b"Rar!\x1a\x07"


class Budzet:
    """Łączny limit bajtów rozpakowanych z jednego analizowanego pliku."""

    def __init__(self, limit_bajtow: int):
        self.pozostalo = limit_bajtow

    def pobierz(self, n: int) -> bool:
        if n > self.pozostalo:
            return False
        self.pozostalo -= n
        return True

    def zwroc(self, n: int) -> None:
        self.pozostalo += n


class _PrzekroczonoBudzet(Exception):
    pass


class _ZleHaslo(Exception):
    pass


class _ZaDuzoPozycji(Exception):
    pass


def hasla_z_tekstu(tekst: str | None) -> list[str]:
    hasla: list[str] = []
    for kandydat in _HASLO.findall(tekst or ""):
        kandydat = kandydat.rstrip(".,;")
        if kandydat and kandydat not in hasla and kandydat != HASLO_DOMYSLNE:
            hasla.append(kandydat)
        if len(hasla) >= MAKS_HASEL:
            break
    return hasla + [HASLO_DOMYSLNE]


def _rodzaj(dane: bytes) -> str | None:
    if dane.startswith(MAGIC_ZIP):
        return "zip"
    if dane.startswith(MAGIC_7Z):
        return "7z"
    if dane.startswith(MAGIC_RAR):
        return "rar"
    return None


def jest_archiwum(z: Zalacznik) -> bool:
    return _rodzaj(z.dane) is not None


def _dziecko(nazwa: str, dane: bytes) -> Zalacznik:
    typ = mimetypes.guess_type(nazwa)[0] or "application/octet-stream"
    return zalacznik_z_danych(nazwa.rsplit("/", 1)[-1] or nazwa, typ, dane)


def _dodaj(wynik: list[Zalacznik], dziecko: Zalacznik) -> None:
    if len(wynik) >= MAKS_POZYCJI:
        raise _ZaDuzoPozycji
    wynik.append(dziecko)


def _czytaj(strumien, budzet: Budzet) -> bytes:
    bufor = io.BytesIO()
    while kawalek := strumien.read(_KAWALEK):
        if not budzet.pobierz(len(kawalek)):
            budzet.zwroc(bufor.tell())  # przerwany plik nie zostaje w pamięci
            raise _PrzekroczonoBudzet
        bufor.write(kawalek)
    return bufor.getvalue()


# --- zip -------------------------------------------------------------------

def _zip(dane: bytes, haslo: str | None, budzet: Budzet, wynik: list[Zalacznik]) -> None:
    with pyzipper.AESZipFile(io.BytesIO(dane)) as zf:
        pozycje = [i for i in zf.infolist() if not i.is_dir()]
        if haslo is None and any(i.flag_bits & 0x1 for i in pozycje):
            raise _ZleHaslo
        for info in pozycje:
            try:
                with zf.open(info, pwd=haslo.encode() if haslo else None) as f:
                    dane_pliku = _czytaj(f, budzet)
                _dodaj(wynik, _dziecko(info.filename, dane_pliku))
            except RuntimeError as e:  # złe hasło
                raise _ZleHaslo from e
            except zipfile.BadZipFile as e:
                if info.flag_bits & 0x1:  # ZipCrypto przy złym haśle psuje CRC
                    raise _ZleHaslo from e
                raise


# --- 7z --------------------------------------------------------------------

class _Py7zBudzetIO(Py7zIO):
    def __init__(self, budzet: Budzet):
        self.budzet = budzet
        self.bufor = io.BytesIO()

    def write(self, s):
        if not self.budzet.pobierz(len(s)):
            raise _PrzekroczonoBudzet
        return self.bufor.write(s)

    def read(self, size=None):
        return self.bufor.read(size)

    def seek(self, offset, whence=0):
        return self.bufor.seek(offset, whence)

    def flush(self):
        return None

    def size(self):
        return self.bufor.getbuffer().nbytes


class _Fabryka7z(WriterFactory):
    def __init__(self, budzet: Budzet):
        self.budzet = budzet
        self.produkty: dict[str, _Py7zBudzetIO] = {}

    def create(self, filename: str) -> Py7zIO:
        if len(self.produkty) >= MAKS_POZYCJI:
            raise _ZaDuzoPozycji
        self.produkty[filename] = _Py7zBudzetIO(self.budzet)
        return self.produkty[filename]


def _7z(dane: bytes, haslo: str | None, budzet: Budzet, wynik: list[Zalacznik]) -> None:
    fabryka = _Fabryka7z(budzet)

    def gotowe(bez_ostatniego: bool) -> None:
        pozycje = list(fabryka.produkty.items())
        for nazwa, p in pozycje[:-1] if bez_ostatniego else pozycje:
            wynik.append(_dziecko(nazwa, p.bufor.getvalue()))

    try:
        with py7zr.SevenZipFile(io.BytesIO(dane), password=haslo) as a:
            if haslo is None and a.needs_password():
                raise _ZleHaslo
            a.extractall(factory=fabryka)
    except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.CrcError) as e:
        raise _ZleHaslo from e
    except (_PrzekroczonoBudzet, _ZaDuzoPozycji):
        if fabryka.produkty:  # ostatni plik przerwany w trakcie zapisu — zwolnij jego bajty
            budzet.zwroc(list(fabryka.produkty.values())[-1].size())
        gotowe(bez_ostatniego=True)
        raise
    except Exception as e:
        if haslo is not None:
            raise _ZleHaslo from e  # zły klucz AES daje różne błędy dekompresji
        raise
    gotowe(bez_ostatniego=False)


# --- rar -------------------------------------------------------------------

def _rar(dane: bytes, haslo: str | None, budzet: Budzet, wynik: list[Zalacznik]) -> None:
    with rarfile.RarFile(io.BytesIO(dane)) as rf:
        if haslo is None and rf.needs_password():
            raise _ZleHaslo
        if haslo:
            rf.setpassword(haslo)
        for info in rf.infolist():
            if info.is_dir():
                continue
            try:
                with rf.open(info) as f:
                    dane_pliku = _czytaj(f, budzet)
            except (rarfile.PasswordRequired, rarfile.BadRarFile, rarfile.RarWrongPassword) as e:
                raise _ZleHaslo from e
            _dodaj(wynik, _dziecko(info.filename, dane_pliku))


_ROZPAKOWYWACZE = {"zip": _zip, "7z": _7z, "rar": _rar}


def rozpakuj(z: Zalacznik, hasla: list[str], budzet: Budzet) -> list[Ostrzezenie]:
    """Wypełnia z.dzieci. Zwraca ostrzeżenia; nigdy nie rzuca wyjątku.

    Przy przekroczeniu limitu zostawia pliki przeczytane do tego momentu.
    """
    rodzaj = _rodzaj(z.dane)
    if rodzaj is None:
        return []
    funkcja = _ROZPAKOWYWACZE[rodzaj]
    for haslo in [None, *hasla]:
        wynik: list[Zalacznik] = []
        try:
            funkcja(z.dane, haslo, budzet, wynik)
        except _ZleHaslo:
            continue
        except _PrzekroczonoBudzet:
            z.dzieci = wynik
            return [Ostrzezenie("LIMIT_ROZPAKOWANIE", f"Przerwano rozpakowywanie {z.nazwa}: przekroczono limit rozmiaru.")]
        except _ZaDuzoPozycji:
            z.dzieci = wynik
            return [Ostrzezenie("LIMIT_ROZPAKOWANIE", f"Archiwum {z.nazwa} ma ponad {MAKS_POZYCJI} plików — pokazano pierwsze {MAKS_POZYCJI}.")]
        except rarfile.RarCannotExec:
            return [Ostrzezenie("BRAK_NARZEDZIA", f"Brak narzędzia do rozpakowania RAR ({z.nazwa}).")]
        except Exception:
            z.dzieci = wynik
            return [Ostrzezenie("ARCHIWUM_USZKODZONE", f"Archiwum {z.nazwa} jest uszkodzone.")]
        z.dzieci = wynik
        z.zaszyfrowany = False
        z.haslo = haslo
        if not wynik:
            return [Ostrzezenie("ARCHIWUM_USZKODZONE", f"Archiwum {z.nazwa} jest puste lub uszkodzone.")]
        return []
    z.zaszyfrowany = True
    z.dzieci = []
    return [Ostrzezenie("ZASZYFROWANE", f"Archiwum {z.nazwa} jest zaszyfrowane, hasło nieznane.")]
