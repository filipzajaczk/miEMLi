"""Szyfrowanie kluczy Joe i plików w kolejce (libsodium SealedBox: X25519 + XSalsa20-Poly1305).

web ma wyłącznie klucz publiczny — potrafi zaszyfrować, ale nie odczytać. Klucz prywatny ma tylko
worker. Tekst jawny zawiera identyfikator właściciela, więc szyfrogramu nie da się podstawić pod
innego użytkownika ani inne zgłoszenie.
"""

import base64
import binascii

from django.conf import settings
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox


class BladOdszyfrowania(Exception):
    pass


class BrakKluczaPrywatnego(BladOdszyfrowania):
    """Błąd konfiguracji workera — nie wina klucza analityka."""


def nowa_para() -> tuple[str, str]:
    prywatny = PrivateKey.generate()
    return (base64.b64encode(bytes(prywatny.public_key)).decode(),
            base64.b64encode(bytes(prywatny)).decode())


def _zaszyfruj(tekst: bytes) -> str:
    publiczny = PublicKey(base64.b64decode(settings.JOE_KLUCZ_PUBLICZNY))
    return base64.b64encode(SealedBox(publiczny).encrypt(tekst)).decode()


def _odszyfruj(szyfrogram: str) -> bytes:
    if not settings.JOE_KLUCZ_PRYWATNY:
        raise BrakKluczaPrywatnego("brak JOE_KLUCZ_PRYWATNY w workerze")
    try:
        prywatny = PrivateKey(base64.b64decode(settings.JOE_KLUCZ_PRYWATNY))
        return SealedBox(prywatny).decrypt(base64.b64decode(szyfrogram, validate=True))
    except (CryptoError, binascii.Error, ValueError, TypeError) as e:
        raise BladOdszyfrowania("nie można odszyfrować") from e


def _rozdziel(tekst: bytes, identyfikator: int) -> bytes:
    prefiks = f"{identyfikator}:".encode()
    if not tekst.startswith(prefiks):
        raise BladOdszyfrowania("szyfrogram należy do innego właściciela")
    return tekst[len(prefiks):]


def zaszyfruj_klucz(uzytkownik_id: int, klucz: str) -> str:
    return _zaszyfruj(f"{uzytkownik_id}:{klucz}".encode())


def odszyfruj_klucz(uzytkownik_id: int, szyfrogram: str) -> str:
    return _rozdziel(_odszyfruj(szyfrogram), uzytkownik_id).decode()


def zaszyfruj_plik(zgloszenie_id: int, dane: bytes) -> str:
    return _zaszyfruj(f"{zgloszenie_id}:".encode() + dane)


def odszyfruj_plik(zgloszenie_id: int, szyfrogram: str) -> bytes:
    return _rozdziel(_odszyfruj(szyfrogram), zgloszenie_id)
