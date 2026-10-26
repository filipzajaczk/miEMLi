"""Jednolity model wiadomości dla .eml i .msg. Bez Django, bez sieci."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Ostrzezenie:
    # KODOWANIE | NAGLOWEK | LIMIT_ROZMIAR | LIMIT_GLEBOKOSC | LIMIT_ROZPAKOWANIE | ZASZYFROWANE
    # | ARCHIWUM_USZKODZONE | BRAK_NARZEDZIA | MSG_BEZ_NAGLOWKOW | USZKODZONA_WIADOMOSC
    kod: str
    opis: str


@dataclass
class Zalacznik:
    nazwa: str
    typ_mime: str
    rozmiar: int
    md5: str
    sha1: str
    sha256: str
    dane: bytes = field(repr=False)
    content_id: str | None = None
    inline: bool = False
    zaszyfrowany: bool = False
    haslo: str | None = None  # hasło, którym udało się rozpakować archiwum (None = bez hasła)
    dzieci: list["Zalacznik"] = field(default_factory=list)
    wiadomosc: "Wiadomosc | None" = None


@dataclass
class Wiadomosc:
    id: str
    naglowki: list[tuple[str, str]]
    temat: str | None
    od: str | None
    do: list[str]
    data: datetime | None
    tekst: str | None
    html: str | None
    zalaczniki: list[Zalacznik]
    ostrzezenia: list[Ostrzezenie]

    def naglowek(self, nazwa: str) -> str | None:
        wszystkie = self.naglowki_wszystkie(nazwa)
        return wszystkie[0] if wszystkie else None

    def naglowki_wszystkie(self, nazwa: str) -> list[str]:
        nazwa = nazwa.lower()
        return [v for k, v in self.naglowki if k.lower() == nazwa]


@dataclass(frozen=True)
class Limity:
    max_rozmiar: int = 50 * 1024 * 1024
    max_glebokosc: int = 5
    max_rozpakowane: int = 200 * 1024 * 1024


class BladParsowania(Exception):
    pass


class NieobslugiwanyPlik(BladParsowania):
    pass


class PlikZaDuzy(BladParsowania):
    pass


def zalacznik_z_danych(nazwa: str, typ_mime: str, dane: bytes, **kw) -> Zalacznik:
    return Zalacznik(
        nazwa=nazwa,
        typ_mime=typ_mime,
        rozmiar=len(dane),
        md5=hashlib.md5(dane).hexdigest(),
        sha1=hashlib.sha1(dane).hexdigest(),
        sha256=hashlib.sha256(dane).hexdigest(),
        dane=dane,
        **kw,
    )
