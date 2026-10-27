"""Profil analityka: klucz Joe Sandbox (zapis szyfrogramu, nigdy odczyt)."""

import re

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.shortcuts import redirect, render
from django.utils import timezone

from .joe_zadania import zlec_sprawdzenie_klucza
from .klucze_joe import zaszyfruj_klucz
from .models import Zdarzenie, profil_dla

FORMAT_KLUCZA = re.compile(r"[A-Za-z0-9]{20,128}")


@sensitive_post_parameters("klucz_joe")
@sensitive_variables("klucz")
@login_required
def profil(request):
    p = profil_dla(request.user)
    blad = None
    wlaczone = bool(settings.JOE_KLUCZ_PUBLICZNY)
    if request.method == "POST" and not wlaczone:
        blad = "Integracja z Joe Sandbox nie jest skonfigurowana."
    elif request.method == "POST":
        akcja = request.POST.get("akcja")
        if akcja == "zapisz":
            klucz = request.POST.get("klucz_joe", "").strip()
            if not FORMAT_KLUCZA.fullmatch(klucz):
                blad = "Nieprawidłowy format klucza Joe."
            else:
                p.joe_klucz_szyfr = zaszyfruj_klucz(request.user.pk, klucz)
                p.joe_klucz_koncowka = klucz[-4:]
                p.joe_klucz_stan = "sprawdzanie"
                p.joe_klucz_zmieniono = timezone.now()
                p.save()
                Zdarzenie.objects.create(uzytkownik=request.user, typ="joe_klucz_ustawiony")
                if not zlec_sprawdzenie_klucza(request.user.pk):
                    p.joe_klucz_stan = "nieznany"
                    p.save(update_fields=["joe_klucz_stan"])
                return redirect("profil")
        elif akcja == "usun":
            p.joe_klucz_szyfr = None
            p.joe_klucz_koncowka = ""
            p.joe_klucz_stan = "nieznany"
            p.joe_klucz_zmieniono = timezone.now()
            p.save()
            Zdarzenie.objects.create(uzytkownik=request.user, typ="joe_klucz_usuniety")
            return redirect("profil")
    return render(request, "analizy/profil.html", {"profil": p, "blad": blad, "joe_wlaczone": wlaczone})
