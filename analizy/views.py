import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.http import require_POST

from mailcore.model import NieobslugiwanyPlik, PlikZaDuzy

from . import prezentacja
from .forms import UploadForm
from .models import Analiza, Zdarzenie
from .uslugi import utworz_lub_otworz
from .zadania import zaplanuj

logger = logging.getLogger(__name__)

KOMUNIKAT_NIE_MAIL = "Plik nie jest prawidłową wiadomością .eml ani .msg."
KOMUNIKAT_ZA_DUZY = "Plik jest większy niż 50 MB."
KOMUNIKAT_BLAD = "Nie udało się przeanalizować pliku."

CSP_PODGLADU = "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
SZABLON_PODGLADU = (
    "<!doctype html><html><head><meta charset=\"utf-8\"><style>"
    "body{font-family:system-ui,sans-serif;font-size:14px;margin:16px;color:#222;background:#fff}"
    ".link{color:#0645ad;text-decoration:underline;cursor:help}"
    "img{max-width:100%;height:auto}"
    "</style></head><body>{tresc}</body></html>"
)


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


def _zapisz_otwarcie(request, analiza: Analiza) -> None:
    klucz = f"otwarto_{analiza.pk}"
    if not request.session.get(klucz):
        Zdarzenie.objects.create(uzytkownik=request.user, analiza=analiza, typ="otwarcie")
        request.session[klucz] = True
        zaplanuj(analiza, tylko_brakujace=True)  # np. klucz API dodany po utworzeniu analizy


@login_required
def szczegoly(request, pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    sekcja = request.GET.get("sekcja", "wiadomosc")
    if sekcja not in dict(prezentacja.SEKCJE):
        raise Http404("Nieznana sekcja")
    wiadomosci = prezentacja.wiadomosci(analiza.wynik)
    wid = request.GET.get("wiadomosc", "0")
    if wid not in wiadomosci:
        raise Http404("Nie ma takiej wiadomości")
    _zapisz_otwarcie(request, analiza)

    w = wiadomosci[wid]
    analiza_w = analiza.wynik["analiza"][wid]
    ioc = prezentacja.drzewo_ioc(analiza)
    kontekst = {
        "analiza": analiza,
        "sekcja": sekcja,
        "sekcje": prezentacja.SEKCJE,
        "wid": wid,
        "w": w,
        "a": analiza_w,
        "wiadomosci": wiadomosci,
        "ioc": ioc,
        "hopy": prezentacja.hopy(analiza_w["received"]),
        "liczniki": {
            "naglowki": len(w["naglowki"]),
            "received": len(analiza_w["received"]),
            "zalaczniki": prezentacja.liczba_zalacznikow(w),
            "linki": len(analiza_w["linki"]),
            "ioc": len(ioc),
        },
    }
    kontekst["wzbogacenia"], kontekst["trwa"] = prezentacja.widoki_wzbogacen(analiza)
    szablon = "analizy/_glowna.html" if request.headers.get("HX-Request") else "analizy/szczegoly.html"
    return render(request, szablon, kontekst)


@login_required
def szczegoly_ioc(request, pk, ioc_pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    ioc = get_object_or_404(analiza.ioc, pk=ioc_pk)
    wzbogacenia, _ = prezentacja.widoki_wzbogacen(analiza)
    return render(request, "analizy/_szczegoly_ioc.html", {"i": ioc, "wz": wzbogacenia[ioc.pk]})


@login_required
@require_POST
def odswiez(request, pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    n = zaplanuj(analiza, wymus=True)
    Zdarzenie.objects.create(uzytkownik=request.user, analiza=analiza, typ="odswiezenie", szczegoly={"zadania": n})
    return redirect("analizy:szczegoly", pk=analiza.pk)


@login_required
def wzbogacenie(request, pk):
    """Fragmenty OOB dla odpytywania htmx: panel IOC, tabela IOC i sam element odpytujący."""
    analiza = get_object_or_404(Analiza, pk=pk)
    wzbogacenia, trwa = prezentacja.widoki_wzbogacen(analiza)
    return render(request, "analizy/_wzbogacenie_oob.html", {
        "analiza": analiza, "ioc": prezentacja.drzewo_ioc(analiza), "wzbogacenia": wzbogacenia,
        "trwa": trwa, "wid": "0",
    })


@login_required
@xframe_options_sameorigin
def podglad(request, pk, wid):
    analiza = get_object_or_404(Analiza, pk=pk)
    w = prezentacja.wiadomosci(analiza.wynik).get(wid)
    if w is None:
        raise Http404("Nie ma takiej wiadomości")
    odpowiedz = HttpResponse(SZABLON_PODGLADU.replace("{tresc}", w.get("html_bezpieczny") or ""))
    odpowiedz["Content-Security-Policy"] = CSP_PODGLADU
    odpowiedz["X-Content-Type-Options"] = "nosniff"
    odpowiedz["Referrer-Policy"] = "no-referrer"
    return odpowiedz
