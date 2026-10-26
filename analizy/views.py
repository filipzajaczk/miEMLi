import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from mailcore.model import NieobslugiwanyPlik, PlikZaDuzy

from .forms import UploadForm
from .models import Analiza
from .uslugi import utworz_lub_otworz

logger = logging.getLogger(__name__)

KOMUNIKAT_NIE_MAIL = "Plik nie jest prawidłową wiadomością .eml ani .msg."
KOMUNIKAT_ZA_DUZY = "Plik jest większy niż 50 MB."
KOMUNIKAT_BLAD = "Nie udało się przeanalizować pliku."


def _lista(request, form=None, blad=None, status=200):
    analizy = Analiza.objects.select_related("utworzyl")[:50]
    return render(
        request,
        "analizy/lista.html",
        {"analizy": analizy, "form": form or UploadForm(), "blad": blad},
        status=status,
    )


@login_required
def lista(request):
    return _lista(request)


@login_required
@require_POST
def upload(request):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        # MemoryFileUploadHandler pomija pliki ponad limit — wtedy formularz widzi brak pliku
        za_duzy = int(request.META.get("CONTENT_LENGTH") or 0) > settings.MAKS_ROZMIAR_PLIKU
        return _lista(request, form, KOMUNIKAT_ZA_DUZY if za_duzy else None)
    plik = form.cleaned_data["plik"]
    try:
        analiza, _ = utworz_lub_otworz(plik.read(), plik.name, request.user)
    except NieobslugiwanyPlik:
        return _lista(request, form, KOMUNIKAT_NIE_MAIL)
    except PlikZaDuzy:
        return _lista(request, form, KOMUNIKAT_ZA_DUZY)
    except Exception:
        logger.exception("Błąd analizy pliku (rozmiar %s B)", plik.size)
        return _lista(request, form, KOMUNIKAT_BLAD)
    return redirect("analizy:szczegoly", pk=analiza.pk)


@login_required
def szczegoly(request, pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    return render(request, "analizy/szczegoly.html", {"analiza": analiza})
