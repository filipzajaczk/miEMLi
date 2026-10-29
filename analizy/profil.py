"""Profil analityka: klucz Joe Sandbox (zapis szyfrogramu, nigdy odczyt) i zmiana hasła."""

import re

from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.views.decorators.http import require_POST
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.shortcuts import redirect, render
from django.utils import timezone

from .joe_zadania import zlec_sprawdzenie_klucza
from .klucze_joe import zaszyfruj_klucz
from .models import Zdarzenie, profil_dla

FORMAT_KLUCZA = re.compile(r"[A-Za-z0-9]{20,128}")


class FormularzHasla(PasswordChangeForm):
    """Same pola, bez opisów — reguły haseł działają nadal i wracają jako komunikaty błędów."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for pole in self.fields.values():
            pole.help_text = ""
            pole.widget.attrs.pop("autofocus", None)
        self.fields["old_password"].label = "Obecne hasło"
        self.fields["new_password1"].label = "Nowe hasło"
        self.fields["new_password2"].label = "Powtórz nowe hasło"


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
    return _strona(request, p, blad)


def _strona(request, p, blad=None, form_hasla=None, status=200):
    return render(request, "analizy/profil.html", {
        "profil": p, "blad": blad, "joe_wlaczone": bool(settings.JOE_KLUCZ_PUBLICZNY),
        "form_hasla": form_hasla or FormularzHasla(request.user),
        "haslo_zmienione": request.session.pop("haslo_zmienione", False),
    }, status=status)


@sensitive_post_parameters("old_password", "new_password1", "new_password2")
@login_required
@require_POST
def zmien_haslo(request):
    form = FormularzHasla(request.user, request.POST)
    if not form.is_valid():
        return _strona(request, profil_dla(request.user), form_hasla=form)
    form.save()
    # Bieżąca sesja zostaje; pozostałe tracą ważność, bo skrót sesji zależy od hasła
    update_session_auth_hash(request, form.user)
    Zdarzenie.objects.create(uzytkownik=request.user, typ="haslo_zmienione")
    request.session["haslo_zmienione"] = True
    return redirect("profil")
