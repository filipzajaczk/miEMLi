"""Wysyłka całego maila do Joe Sandbox: zlecenie (web) i zadania workera.

Do kolejki trafia wyłącznie szyfrogram pliku (klucz publiczny); worker odszyfrowuje plik i klucz Joe
analityka tylko w pamięci zadania. Logi: identyfikator zgłoszenia i status — nigdy klucz ani nazwa pliku.
"""

import hashlib
import logging
from datetime import timedelta

import django_rq
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from integracje import joe

from .klucze_joe import BladOdszyfrowania, BrakKluczaPrywatnego, odszyfruj_klucz, odszyfruj_plik, zaszyfruj_plik
from .models import ProfilAnalityka, ZgloszenieJoe, Zdarzenie, profil_dla

logger = logging.getLogger(__name__)

DUPLIKAT = timedelta(minutes=10)
SLEDZENIE_CO = 30
SLEDZENIE_MAKS = timedelta(hours=2)
OPOZNIENIA = {"limit": (60, 300), "niedostepny": (30, 120)}


class BladZlecenia(Exception):
    pass


def _kolejkuj(funkcja, *args, opoznienie: int = 0) -> bool:
    """Zadania Joe nie zostają w Redisie po wykonaniu (także po błędzie). False = kolejka niedostępna."""
    try:
        kolejka = django_rq.get_queue("default")
        if opoznienie:
            kolejka.enqueue_in(timedelta(seconds=opoznienie), funkcja, *args, result_ttl=0, failure_ttl=0)
        else:
            kolejka.enqueue(funkcja, *args, result_ttl=0, failure_ttl=0)
        return True
    except Exception:
        logger.warning("Nie udało się zakolejkować zadania Joe (Redis niedostępny?)")
        return False


def zlec_wysylke(analiza, uzytkownik, dane: bytes) -> ZgloszenieJoe:
    if not settings.JOE_KLUCZ_PUBLICZNY:
        raise BladZlecenia("Integracja z Joe Sandbox nie jest skonfigurowana.")
    if hashlib.sha256(dane).hexdigest() != analiza.sha256:
        raise BladZlecenia("To nie jest ten sam plik co w analizie.")
    with transaction.atomic():
        # blokada wiersza profilu serializuje równoczesne zlecenia tego analityka (podwójne kliknięcie)
        profil_dla(uzytkownik)
        profil = ProfilAnalityka.objects.select_for_update().get(uzytkownik=uzytkownik)
        if not profil.joe_klucz_szyfr:
            raise BladZlecenia("Ustaw klucz Joe w profilu.")
        teraz = timezone.now()
        # nieudane zgłoszenia nie blokują ponowienia ani nie zużywają limitu
        udane = ZgloszenieJoe.objects.filter(uzytkownik=uzytkownik).exclude(status__in=("blad", "limit"))
        if udane.filter(analiza=analiza, utworzono__gte=teraz - DUPLIKAT).exists():
            raise BladZlecenia("Już wysłano — poczekaj na wynik.")
        polnoc = timezone.localtime(teraz).replace(hour=0, minute=0, second=0, microsecond=0)
        if udane.filter(utworzono__gte=polnoc).count() >= settings.JOE_LIMIT_DZIENNY:
            raise BladZlecenia("Osiągnięto dzienny limit wysyłek do Joe.")
        zgloszenie = ZgloszenieJoe.objects.create(analiza=analiza, uzytkownik=uzytkownik, status="zlecone")
        Zdarzenie.objects.create(uzytkownik=uzytkownik, analiza=analiza, typ="joe_wyslanie",
                                 szczegoly={"zgloszenie": zgloszenie.pk})
        szyfrogram = zaszyfruj_plik(zgloszenie.pk, dane)
        transaction.on_commit(lambda: _po_zapisie(zgloszenie.pk, szyfrogram))
    return zgloszenie


def _po_zapisie(zgloszenie_id: int, szyfrogram: str) -> None:
    if not _kolejkuj(wyslij_do_joe, zgloszenie_id, szyfrogram):
        ZgloszenieJoe.objects.filter(pk=zgloszenie_id).update(
            status="blad", blad="Kolejka zadań niedostępna — spróbuj ponownie za chwilę.")


def zlec_sprawdzenie_klucza(uzytkownik_id: int) -> bool:
    return _kolejkuj(sprawdz_klucz_joe, uzytkownik_id)


def _ustaw(zgloszenie: ZgloszenieJoe, **pola) -> None:
    for k, v in pola.items():
        setattr(zgloszenie, k, v)
    zgloszenie.save(update_fields=list(pola))
    logger.info("joe zgloszenie=%s status=%s", zgloszenie.pk, zgloszenie.status)


def _klucz_analityka(zgloszenie: ZgloszenieJoe) -> str | None:
    profil = profil_dla(zgloszenie.uzytkownik)
    if not profil.joe_klucz_szyfr:
        return None
    try:
        return odszyfruj_klucz(zgloszenie.uzytkownik_id, profil.joe_klucz_szyfr)
    except BrakKluczaPrywatnego:
        logger.error("Worker bez JOE_KLUCZ_PRYWATNY — wysyłki do Joe niemożliwe")
        return None
    except BladOdszyfrowania:
        ProfilAnalityka.objects.filter(pk=profil.pk).update(joe_klucz_stan="odrzucony")
        return None


def wyslij_do_joe(zgloszenie_id: int, szyfrogram: str, proba: int = 0) -> None:
    # atomowe przejęcie: powtórzone/podmienione zadanie nie wyśle maila drugi raz
    if not ZgloszenieJoe.objects.filter(pk=zgloszenie_id, status="zlecone").update(status="wysylanie"):
        return
    zgloszenie = ZgloszenieJoe.objects.select_related("analiza").get(pk=zgloszenie_id)
    try:
        _wyslij(zgloszenie, szyfrogram, proba)
    except Exception:
        logger.exception("joe zgloszenie=%s nieoczekiwany błąd wysyłki", zgloszenie_id)
        _ustaw(zgloszenie, status="blad", blad="Błąd wewnętrzny wysyłki.")


def _wyslij(zgloszenie: ZgloszenieJoe, szyfrogram: str, proba: int) -> None:
    try:
        dane = odszyfruj_plik(zgloszenie.pk, szyfrogram)
    except BladOdszyfrowania:
        return _ustaw(zgloszenie, status="blad", blad="Błąd wewnętrzny wysyłki.")
    klucz = _klucz_analityka(zgloszenie)
    if klucz is None:
        return _ustaw(zgloszenie, status="blad", blad="Ustaw ponownie klucz Joe w profilu.")
    rozszerzenie = "msg" if zgloszenie.analiza.nazwa_pliku.lower().endswith(".msg") else "eml"
    wynik = joe.wyslij(klucz, dane, f"analiza-{zgloszenie.analiza_id}.{rozszerzenie}",
                       f"miemli, analiza #{zgloszenie.analiza_id}", settings.JOE_API_URL)
    if wynik.status == "ok":
        _ustaw(zgloszenie, status="wyslane", id_zgloszenia=wynik.dane["id_zgloszenia"], wyslano=timezone.now())
        _kolejkuj(sprawdz_joe, zgloszenie.pk, opoznienie=SLEDZENIE_CO)
        return
    opoznienia = OPOZNIENIA.get(wynik.status, ())
    if wynik.ponawiac and proba < len(opoznienia):
        logger.info("joe zgloszenie=%s ponowienie=%s status=%s", zgloszenie.pk, proba + 1, wynik.status)
        _ustaw(zgloszenie, status="zlecone")
        if not _kolejkuj(wyslij_do_joe, zgloszenie.pk, szyfrogram, proba + 1, opoznienie=opoznienia[proba]):
            _ustaw(zgloszenie, status="blad", blad="Kolejka zadań niedostępna — spróbuj ponownie za chwilę.")
        return
    _oznacz_klucz(zgloszenie, wynik)
    _ustaw(zgloszenie, status="limit" if wynik.status == "limit" else "blad", blad=wynik.blad)


def _oznacz_klucz(zgloszenie: ZgloszenieJoe, wynik) -> None:
    """Klucz odrzucony w trakcie wysyłki/śledzenia — analityk od razu widzi to w profilu."""
    if wynik.klucz_odrzucony:
        ProfilAnalityka.objects.filter(uzytkownik_id=zgloszenie.uzytkownik_id).update(joe_klucz_stan="odrzucony")


def sprawdz_joe(zgloszenie_id: int) -> None:
    zgloszenie = ZgloszenieJoe.objects.filter(pk=zgloszenie_id).first()
    if zgloszenie is None or zgloszenie.status not in ZgloszenieJoe.AKTYWNE or not zgloszenie.id_zgloszenia:
        return
    try:
        _sprawdz(zgloszenie)
    except Exception:
        logger.exception("joe zgloszenie=%s nieoczekiwany błąd śledzenia", zgloszenie_id)
        _ustaw(zgloszenie, status="blad", blad="Błąd wewnętrzny śledzenia statusu.")


def _sprawdz(zgloszenie: ZgloszenieJoe) -> None:
    klucz = _klucz_analityka(zgloszenie)
    if klucz is None:
        return _ustaw(zgloszenie, status="blad", blad="Ustaw ponownie klucz Joe w profilu.")
    wynik = joe.stan_zgloszenia(klucz, zgloszenie.id_zgloszenia, settings.JOE_API_URL)
    teraz = timezone.now()
    if wynik.status == "ok":
        d = wynik.dane
        _ustaw(zgloszenie, status=d["status"], webid=d["webid"], werdykt=d["werdykt"], wynik=d["wynik"],
               sprawdzono=teraz)
        if d["status"] == "zakonczone":
            return
    elif not wynik.ponawiac:
        _oznacz_klucz(zgloszenie, wynik)
        return _ustaw(zgloszenie, status="blad", blad=wynik.blad, sprawdzono=teraz)
    if zgloszenie.wyslano and teraz - zgloszenie.wyslano >= SLEDZENIE_MAKS:
        return _ustaw(zgloszenie, status="czas_minal")
    _kolejkuj(sprawdz_joe, zgloszenie.pk, opoznienie=SLEDZENIE_CO)


def sprawdz_klucz_joe(uzytkownik_id: int) -> None:
    profil = ProfilAnalityka.objects.filter(uzytkownik_id=uzytkownik_id).first()
    if profil is None or not profil.joe_klucz_szyfr:
        return
    try:
        klucz = odszyfruj_klucz(uzytkownik_id, profil.joe_klucz_szyfr)
    except BrakKluczaPrywatnego:
        logger.error("Worker bez JOE_KLUCZ_PRYWATNY — nie można sprawdzić klucza Joe")
        return
    except BladOdszyfrowania:
        ProfilAnalityka.objects.filter(pk=profil.pk).update(joe_klucz_stan="odrzucony")
        return
    wynik = joe.info_konta(klucz, settings.JOE_API_URL)
    stan = {"ok": "dziala", "odrzucony": "odrzucony"}.get(wynik.status, "nieznany")
    ProfilAnalityka.objects.filter(pk=profil.pk).update(joe_klucz_stan=stan)
