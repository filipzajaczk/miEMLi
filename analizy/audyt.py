"""Podgląd dziennika zdarzeń — wyłącznie dla administratorów (is_staff). Tylko odczyt."""

import logging
from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden
from django.shortcuts import render

from .models import Zdarzenie

logger = logging.getLogger(__name__)

OPISY_ZDARZEN = {
    "utworzenie": "Utworzenie analizy",
    "otwarcie": "Otwarcie analizy",
    "odswiezenie": "Odświeżenie wzbogacenia",
    "notatka": "Zmiana komentarza",
    "usuniecie": "Usunięcie analizy",
    "analiza_przerwana": "Analiza przerwana (sandbox)",
    "werdykt": "Zmiana werdyktu",
    "joe_wyslanie": "Wysyłka do Joe Sandbox",
    "joe_klucz_ustawiony": "Ustawienie klucza Joe",
    "joe_klucz_usuniety": "Usunięcie klucza Joe",
    "haslo_zmienione": "Zmiana hasła",
}


def _data(tekst):
    try:
        return date.fromisoformat(tekst)
    except (TypeError, ValueError):
        return None


@login_required
def audyt(request):
    if not request.user.is_staff:
        logger.warning("Odmowa dostępu do audytu: %s", request.user.username)
        return HttpResponseForbidden("Brak dostępu.")
    zdarzenia = Zdarzenie.objects.select_related("uzytkownik", "analiza").order_by("-czas", "-pk")
    filtry = {k: request.GET.get(k, "") for k in ("uzytkownik", "typ", "od", "do")}
    if filtry["uzytkownik"].isdigit():
        zdarzenia = zdarzenia.filter(uzytkownik_id=int(filtry["uzytkownik"]))
    if filtry["typ"]:
        zdarzenia = zdarzenia.filter(typ=filtry["typ"])
    if od := _data(filtry["od"]):
        zdarzenia = zdarzenia.filter(czas__date__gte=od)
    if do := _data(filtry["do"]):
        zdarzenia = zdarzenia.filter(czas__date__lte=do)
    strona = Paginator(zdarzenia, 50).get_page(request.GET.get("strona"))
    for z in strona.object_list:
        z.opis = OPISY_ZDARZEN.get(z.typ, z.typ)
    zapytanie = request.GET.copy()
    zapytanie.pop("strona", None)
    return render(request, "analizy/audyt.html", {
        "strona": strona, "filtry": filtry, "zapytanie": zapytanie.urlencode(),
        "uzytkownicy": get_user_model().objects.order_by("username"),
        "typy": sorted(OPISY_ZDARZEN.items(), key=lambda t: t[1]),
    })
