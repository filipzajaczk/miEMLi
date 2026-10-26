"""Tworzenie analizy z pliku: parsowanie, analiza, zapis z deduplikacją."""

import hashlib

from django.conf import settings
from django.db import transaction

from mailcore.analiza import analizuj
from mailcore.model import Limity
from mailcore.parsuj import parsuj
from mailcore.serializacja import bez_nul, do_json

from .models import IOC, Analiza, Zdarzenie
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

    limity = Limity(max_rozmiar=settings.MAKS_ROZMIAR_PLIKU)
    w = parsuj(dane, nazwa, limity)
    wynik = analizuj(w, settings.MIEMLI_IGNOROWANE_DOMENY)

    with transaction.atomic():
        analiza = Analiza.objects.create(
            ticket_id=ticket_id,
            attachment_id=attachment_id,
            sha256=sha256,
            nazwa_pliku=nazwa[:255],
            wynik=do_json(w, wynik),
            utworzyl=uzytkownik,
        )
        po_numerze: dict[int, IOC] = {}
        for i in wynik.ioc:  # rodzic zawsze ma mniejszy numer niż dziecko
            po_numerze[i.id] = IOC.objects.create(
                analiza=analiza,
                numer=i.id,
                typ=i.typ,
                wartosc=bez_nul(i.wartosc),
                etykieta=bez_nul(i.etykieta),
                zrodlo=i.zrodlo,
                hashe=i.hashe,
                rodzic=po_numerze.get(i.rodzic_id),
            )
        Zdarzenie.objects.create(uzytkownik=uzytkownik, analiza=analiza, typ="utworzenie", szczegoly={"plik": nazwa})
        transaction.on_commit(lambda: zaplanuj(analiza))
    return analiza, True
