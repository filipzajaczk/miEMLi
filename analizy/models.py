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
    rodzic = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE, related_name="dzieci")

    class Meta:
        ordering = ["numer"]
        constraints = [models.UniqueConstraint(fields=["analiza", "typ", "wartosc"], name="ioc_unikalny_w_analizie")]
        verbose_name = "IOC"
        verbose_name_plural = "IOC"

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
