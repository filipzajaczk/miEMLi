"""Ręczny smoke test kluczy API: prawdziwe zapytania o znane wskaźniki, bez zapisu do bazy."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from analizy import zadania

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
PROBY = [("gti", "plik", EICAR_SHA256), ("gti", "ip", "8.8.8.8"), ("censys", "ip", "8.8.8.8")]


class Command(BaseCommand):
    help = "Sprawdza klucze GTI i Censys zapytaniami o EICAR i 8.8.8.8 (nic nie zapisuje)."

    def handle(self, *args, **options):
        bledy = 0
        for dostawca in dict.fromkeys(d for d, _, _ in PROBY):
            klucz = settings.GTI_API_KEY if dostawca == "gti" else settings.CENSYS_API_TOKEN
            if not klucz:
                self.stdout.write(f"{dostawca}: brak klucza (w Dockerze uruchom w kontenerze worker)")
                continue
            sprawdz = zadania._klient(dostawca)
            for d, typ, wartosc in PROBY:
                if d != dostawca:
                    continue
                wynik = sprawdz(typ, wartosc)
                linia = f"{dostawca} {typ} {wynik.status}"
                self.stdout.write(f"{linia} — {wynik.blad}" if wynik.blad else linia)
                bledy += wynik.status == "blad"
        if bledy:
            raise CommandError(f"Błędów: {bledy}")
