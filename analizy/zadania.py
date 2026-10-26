"""Wzbogacanie IOC: planowanie lookupów (web) i ich wykonanie (worker RQ)."""

import logging
from datetime import timedelta

import django_rq
from django.conf import settings
from django.utils import timezone

from integracje.censys import KlientCensys
from integracje.gti import KlientGTI
from integracje.wspolne import WynikDostawcy

from .models import Analiza, Wzbogacenie

logger = logging.getLogger(__name__)

CACHE = timedelta(hours=24)
BLOKADA = timedelta(minutes=10)  # tyle czekamy na worker, zanim uznamy zadanie za zagubione
OPOZNIENIA_LIMIT = (30, 120, 300)  # sekundy przed kolejnymi próbami przy HTTP 429
OPOZNIENIA_BLAD = (10, 60)  # przy 5xx, timeoucie i błędzie sieci
DOSTAWCY = {"gti": ("plik", "url", "domena", "ip"), "censys": ("ip",)}


def skonfigurowany(dostawca: str) -> bool:
    if dostawca == "gti":
        return bool(settings.GTI_API_KEY)
    if dostawca == "censys":
        return bool(settings.CENSYS_API_TOKEN)
    return False


def dostawcy_dla(typ: str) -> list[str]:
    return [d for d, typy in DOSTAWCY.items() if typ in typy and skonfigurowany(d)]


def _kolejkuj(funkcja, *args, **kwargs) -> None:
    django_rq.enqueue(funkcja, *args, **kwargs)


def _klient(dostawca: str):
    """Funkcja (typ, wartosc) -> WynikDostawcy dla dostawcy."""
    if dostawca == "gti":
        return KlientGTI(settings.GTI_API_KEY).sprawdz
    if dostawca == "censys":
        klient = KlientCensys(settings.CENSYS_API_TOKEN, settings.CENSYS_ORG_ID)
        return lambda typ, wartosc: klient.sprawdz_ip(wartosc)
    raise ValueError(dostawca)


def _do_sprawdzenia(wpis: Wzbogacenie | None, teraz, wymus: bool, tylko_brakujace: bool) -> bool:
    if wpis is None:
        return True
    if tylko_brakujace:
        return False
    if wymus:
        return True
    if wpis.status == "oczekuje":
        return not wpis.zlecono or teraz - wpis.zlecono >= BLOKADA
    if wpis.status in ("gotowe", "brak_danych"):
        return not wpis.sprawdzono or teraz - wpis.sprawdzono >= CACHE
    return True  # limit, blad


def zaplanuj(analiza: Analiza, wymus: bool = False, tylko_brakujace: bool = False) -> int:
    teraz = timezone.now()
    zakolejkowane = 0
    widziane = set()
    for ioc in analiza.ioc.all():
        for dostawca in dostawcy_dla(ioc.typ):
            klucz = Wzbogacenie.klucz_dla(dostawca, ioc.typ, ioc.wartosc)
            if klucz in widziane:
                continue
            widziane.add(klucz)
            wpis = Wzbogacenie.objects.filter(klucz=klucz).first()
            if not _do_sprawdzenia(wpis, teraz, wymus, tylko_brakujace):
                continue
            Wzbogacenie.objects.update_or_create(
                klucz=klucz,
                defaults={"dostawca": dostawca, "typ": ioc.typ, "wartosc": ioc.wartosc,
                          "status": "oczekuje", "zlecono": teraz},
            )
            _kolejkuj(wzbogac, dostawca, ioc.typ, ioc.wartosc)
            zakolejkowane += 1
    return zakolejkowane


def _zapisz(dostawca: str, typ: str, wartosc: str, wynik: WynikDostawcy) -> None:
    Wzbogacenie.objects.update_or_create(
        klucz=Wzbogacenie.klucz_dla(dostawca, typ, wartosc),
        defaults={
            "dostawca": dostawca, "typ": typ, "wartosc": wartosc, "status": wynik.status,
            "skrot": wynik.skrot, "surowe": wynik.surowe, "link": wynik.link, "blad": wynik.blad,
            "sprawdzono": timezone.now(),
        },
    )


def _ponow(opoznienie_s: int, *args, **kwargs) -> None:
    django_rq.get_queue("default").enqueue_in(timedelta(seconds=opoznienie_s), wzbogac, *args, **kwargs)


def wzbogac(dostawca: str, typ: str, wartosc: str, proba: int = 0) -> None:
    wynik = _klient(dostawca)(typ, wartosc)
    logger.info("wzbogacenie %s %s %s (próba %s)", dostawca, typ, wynik.status, proba)
    opoznienia = OPOZNIENIA_LIMIT if wynik.status == "limit" else OPOZNIENIA_BLAD
    if wynik.ponawiac and proba < len(opoznienia):
        # wpis zostaje "oczekuje"; odświeżone zlecono chroni przed uznaniem za zagubiony
        Wzbogacenie.objects.update_or_create(
            klucz=Wzbogacenie.klucz_dla(dostawca, typ, wartosc),
            defaults={"dostawca": dostawca, "typ": typ, "wartosc": wartosc,
                      "status": "oczekuje", "zlecono": timezone.now()},
        )
        _ponow(opoznienia[proba], dostawca, typ, wartosc, proba=proba + 1)
        return
    _zapisz(dostawca, typ, wartosc, wynik)
