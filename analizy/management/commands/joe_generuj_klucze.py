"""Nowa para kluczy do szyfrowania kluczy Joe. Wypisuje je do wklejenia do .env — nic nie zapisuje."""

from django.core.management.base import BaseCommand

from analizy.klucze_joe import nowa_para


class Command(BaseCommand):
    help = "Generuje parę kluczy: publiczny dla web i workera, prywatny TYLKO dla workera."

    def handle(self, *args, **options):
        publiczny, prywatny = nowa_para()
        self.stdout.write("# Wklej do .env. Klucz prywatny trafia wyłącznie do kontenera worker.")
        self.stdout.write(f"JOE_KLUCZ_PUBLICZNY={publiczny}")
        self.stdout.write(f"JOE_KLUCZ_PRYWATNY={prywatny}")
        self.stdout.write("# Po wymianie pary analitycy muszą ponownie wpisać klucze Joe w profilu.")
