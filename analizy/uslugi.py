"""Tworzenie analizy z pliku: parsowanie, analiza, zapis z deduplikacją."""

import hashlib

from django.conf import settings
from django.db import transaction

from mailcore.serializacja import bez_nul

from .models import IOC, Analiza, Zdarzenie
from .piaskownica_klient import AnalizaPrzerwana, analizuj_w_piaskownicy
from .zadania import zaplanuj


def utworz_lub_otworz(
    dane: bytes,
    nazwa: str,
    uzytkownik,
    ticket_id: int | None = None,
    attachment_id: int | None = None,
) -> tuple[Analiza, bool]:
    """Ten sam plik w tym samym tickecie (lub bez ticketu) → istniejąca analiza."""
    sha256 = hashlib.sha256(dane).hexdigest()
    istniejaca = Analiza.objects.filter(ticket_id=ticket_id, sha256=sha256).first()
    if istniejaca:
        return istniejaca, False

    try:
        wynik = analizuj_w_piaskownicy(dane, nazwa)
    except AnalizaPrzerwana as e:
        Zdarzenie.objects.create(uzytkownik=uzytkownik, typ="analiza_przerwana",
                                 szczegoly={"sha256": sha256, "plik": nazwa[:255], "powod": e.powod})
        raise

    with transaction.atomic():
        analiza = Analiza.objects.create(
            ticket_id=ticket_id,
            attachment_id=attachment_id,
            sha256=sha256,
            nazwa_pliku=nazwa[:255],
            wynik=bez_nul({k: wynik[k] for k in ("wiadomosc", "analiza")} | {"ioc": wynik["ioc"]}),
            temat_wiadomosci=bez_nul(wynik["wiadomosc"].get("temat") or "")[:500],
            utworzyl=uzytkownik,
        )
        po_numerze: dict[int, IOC] = {}
        for i in wynik["ioc"]:  # rodzic zawsze ma mniejszy numer niż dziecko (sprawdza walidacja)
            po_numerze[i["id"]] = IOC.objects.create(
                analiza=analiza,
                numer=i["id"],
                typ=i["typ"],
                wartosc=bez_nul(i["wartosc"]),
                etykieta=bez_nul(i.get("etykieta")),
                zrodlo=(i.get("zrodlo") or "")[:10],
                hashe=i.get("hashe"),
                haslo_archiwum=bez_nul(i["haslo_archiwum"])[:255] if i.get("haslo_archiwum") else None,
                rodzic=po_numerze.get(i.get("rodzic_id")),
            )
        Zdarzenie.objects.create(uzytkownik=uzytkownik, analiza=analiza, typ="utworzenie", szczegoly={"plik": nazwa})
        transaction.on_commit(lambda: zaplanuj(analiza))
    return analiza, True
