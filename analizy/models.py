import hashlib

from django.conf import settings
from django.db import models


class Analiza(models.Model):
    WERDYKTY = [
        ("phishing", "Phishing"),
        ("spam", "Spam"),
        ("czysty", "Czysty"),
        ("do_weryfikacji", "Do weryfikacji"),
    ]

    ticket_id = models.IntegerField(null=True, blank=True)
    attachment_id = models.IntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, db_index=True)
    nazwa_pliku = models.CharField(max_length=255)
    wynik = models.JSONField()
    werdykt = models.CharField(max_length=20, blank=True, choices=WERDYKTY)
    # kopia tematu z wyniku — lista analiz nie musi ładować (dużego) pola wynik
    temat_wiadomosci = models.CharField(max_length=500, blank=True, default="")
    notatka = models.TextField(blank=True)
    utworzyl = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="analizy")
    utworzono = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-utworzono"]
        verbose_name = "analiza"
        verbose_name_plural = "analizy"

    def __str__(self):
        return f"{self.nazwa_pliku} ({self.utworzono:%Y-%m-%d %H:%M})"

    @property
    def temat(self) -> str | None:
        return self.wynik.get("wiadomosc", {}).get("temat")


class IOC(models.Model):
    TYPY = [("plik", "Plik"), ("url", "URL"), ("domena", "Domena"), ("ip", "IP"), ("email", "E-mail")]
    ZRODLA = [("naglowek", "Nagłówek"), ("tresc", "Treść"), ("zalacznik", "Załącznik"), ("qr", "Kod QR")]

    analiza = models.ForeignKey(Analiza, on_delete=models.CASCADE, related_name="ioc")
    numer = models.IntegerField()
    typ = models.CharField(max_length=10, choices=TYPY)
    wartosc = models.TextField()
    etykieta = models.TextField(null=True, blank=True)
    zrodlo = models.CharField(max_length=10, choices=ZRODLA)
    hashe = models.JSONField(null=True, blank=True)
    haslo_archiwum = models.CharField(max_length=255, null=True, blank=True)
    rodzic = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE, related_name="dzieci")

    class Meta:
        # Bez unikalnego indeksu na wartosc: długie URL-e przekraczają limit indeksu btree
        # w Postgresie. Unikalność (typ, wartosc) zapewnia mailcore.analiza.ioc.
        ordering = ["numer"]
        verbose_name = "artefakt"
        verbose_name_plural = "artefakty"

    def __str__(self):
        return f"{self.typ}: {self.wartosc}"


class Zdarzenie(models.Model):
    uzytkownik = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="zdarzenia")
    analiza = models.ForeignKey(Analiza, null=True, blank=True, on_delete=models.CASCADE, related_name="zdarzenia")
    typ = models.CharField(max_length=30)
    szczegoly = models.JSONField(default=dict, blank=True)
    czas = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-czas"]
        verbose_name = "zdarzenie"
        verbose_name_plural = "zdarzenia"

    def __str__(self):
        return f"{self.czas:%Y-%m-%d %H:%M} {self.uzytkownik} {self.typ}"


class Wzbogacenie(models.Model):
    """Wynik lookupu IOC u dostawcy (GTI, Censys). Wspólny dla wszystkich analiz — pełni rolę cache."""

    STATUSY = [
        ("oczekuje", "Oczekuje"),
        ("gotowe", "Gotowe"),
        ("brak_danych", "Brak danych"),
        ("limit", "Limit API"),
        ("blad", "Błąd"),
    ]

    # sha256 z "dostawca:typ:wartosc" — bez indeksu na długiej wartości (limit btree w Postgresie)
    klucz = models.CharField(max_length=64, unique=True)
    dostawca = models.CharField(max_length=10)
    typ = models.CharField(max_length=10)
    wartosc = models.TextField()
    status = models.CharField(max_length=12, choices=STATUSY)
    skrot = models.JSONField(default=dict, blank=True)
    surowe = models.JSONField(null=True, blank=True)
    link = models.TextField(null=True, blank=True)
    blad = models.TextField(blank=True, default="")
    zlecono = models.DateTimeField(null=True, blank=True)
    sprawdzono = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "wzbogacenie"
        verbose_name_plural = "wzbogacenia"

    def __str__(self):
        return f"{self.dostawca} {self.typ}: {self.status}"

    @staticmethod
    def klucz_dla(dostawca: str, typ: str, wartosc: str) -> str:
        return hashlib.sha256(f"{dostawca}:{typ}:{wartosc}".encode()).hexdigest()


class ProfilAnalityka(models.Model):
    STANY = [("nieznany", "Nieznany"), ("sprawdzanie", "Sprawdzanie"), ("dziala", "Działa"),
             ("odrzucony", "Odrzucony")]

    uzytkownik = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profil")
    joe_klucz_szyfr = models.TextField(null=True, blank=True)  # SealedBox — web nie potrafi odczytać
    joe_klucz_koncowka = models.CharField(max_length=4, blank=True, default="")
    joe_klucz_stan = models.CharField(max_length=12, choices=STANY, default="nieznany")
    joe_klucz_zmieniono = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "profil analityka"
        verbose_name_plural = "profile analityków"

    def __str__(self):
        return f"profil {self.uzytkownik}"


def profil_dla(uzytkownik) -> ProfilAnalityka:
    return ProfilAnalityka.objects.get_or_create(uzytkownik=uzytkownik)[0]


class ZgloszenieJoe(models.Model):
    """Wysyłka całego maila do Joe Sandbox (kluczem analityka)."""

    STATUSY = [("zlecone", "Zlecone"), ("wysylanie", "Wysyłanie"), ("wyslane", "Wysłane"), ("w_kolejce", "W kolejce w Joe"),
               ("trwa", "Analiza trwa"), ("zakonczone", "Zakończone"), ("blad", "Błąd"),
               ("limit", "Limit Joe"), ("czas_minal", "Przekroczony czas śledzenia")]
    AKTYWNE = ("zlecone", "wysylanie", "wyslane", "w_kolejce", "trwa")

    analiza = models.ForeignKey(Analiza, on_delete=models.CASCADE, related_name="zgloszenia_joe")
    uzytkownik = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="zgloszenia_joe")
    utworzono = models.DateTimeField(auto_now_add=True)
    wyslano = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=12, choices=STATUSY, default="zlecone")
    id_zgloszenia = models.CharField(max_length=64, null=True, blank=True)
    webid = models.CharField(max_length=64, null=True, blank=True)
    werdykt = models.CharField(max_length=12, null=True, blank=True)
    wynik = models.IntegerField(null=True, blank=True)
    blad = models.TextField(blank=True, default="")
    sprawdzono = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-utworzono"]
        verbose_name = "zgłoszenie Joe"
        verbose_name_plural = "zgłoszenia Joe"

    def __str__(self):
        return f"Joe #{self.pk} analiza {self.analiza_id}: {self.status}"

    @property
    def link(self) -> str | None:
        from integracje.joe import link_analizy

        try:
            return link_analizy(self.webid) if self.webid else None
        except ValueError:
            return None
