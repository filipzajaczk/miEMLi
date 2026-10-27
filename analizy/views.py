import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.http import require_POST

from mailcore.html_bezpieczny import ponownie_oczysc
from mailcore.model import NieobslugiwanyPlik, PlikZaDuzy

from . import prezentacja
from .forms import UploadForm
from .models import Analiza, Zdarzenie
from .piaskownica_klient import AnalizaPrzerwana, PiaskownicaNiedostepna
from .uslugi import utworz_lub_otworz
from .zadania import zaplanuj

logger = logging.getLogger(__name__)

KOMUNIKAT_NIE_MAIL = "Plik nie jest prawidłową wiadomością .eml ani .msg."
KOMUNIKAT_ZA_DUZY = "Plik jest większy niż 50 MB."
KOMUNIKAT_BLAD = "Nie udało się przeanalizować pliku."
KOMUNIKAT_NIEDOSTEPNY = "Sandbox analizy niedostępny — spróbuj za chwilę."
_PRZERWANA = "Analiza przerwana: {}. Plik może być złośliwy lub uszkodzony — przeanalizuj go w Joe Sandbox."
KOMUNIKATY_PRZERWANIA = {
    "czas": _PRZERWANA.format("przekroczony czas"),
    "pamiec": _PRZERWANA.format("przekroczony limit pamięci"),
    "awaria": _PRZERWANA.format("parser przerwał pracę"),
    "nieprawidlowa_odpowiedz": "Nieprawidłowy wynik analizy.",
}

# sandbox: nawet otwarty bezpośrednio (nie w iframe) podgląd działa w osobnym, pustym originie
CSP_PODGLADU = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox"
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
    except AnalizaPrzerwana as e:
        if e.powod in ("awaria", "nieprawidlowa_odpowiedz"):
            logger.warning("Sandbox: analiza przerwana (%s) — możliwa próba exploita", e.powod)
        return _lista(request, form, KOMUNIKATY_PRZERWANIA[e.powod])
    except PiaskownicaNiedostepna:
        logger.warning("Sandbox analizy niedostępny")
        return _lista(request, form, KOMUNIKAT_NIEDOSTEPNY)
    except Exception:
        logger.exception("Błąd analizy pliku (rozmiar %s B)", plik.size)
        return _lista(request, form, KOMUNIKAT_BLAD)
    return redirect("analizy:szczegoly", pk=analiza.pk)


def _zapisz_otwarcie(request, analiza: Analiza) -> None:
    klucz = f"otwarto_{analiza.pk}"
    if not request.session.get(klucz):
        Zdarzenie.objects.create(uzytkownik=request.user, analiza=analiza, typ="otwarcie")
        request.session[klucz] = True


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
    zaplanuj(analiza, tylko_brakujace=True)  # np. klucz API dodany po utworzeniu analizy

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


MAKS_NOTATKA = 10000


@login_required
def opcje(request, pk):
    """Rozwinięcie wiersza na liście analiz: komentarz i usuwanie."""
    analiza = get_object_or_404(Analiza, pk=pk)
    return render(request, "analizy/_opcje.html", {"analiza": analiza})


@login_required
@require_POST
def notatka(request, pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    tresc = request.POST.get("notatka", "").replace("\x00", "")
    if len(tresc) > MAKS_NOTATKA:
        return render(request, "analizy/_opcje.html", {
            "analiza": analiza, "tresc": tresc, "blad": f"Komentarz może mieć maksymalnie {MAKS_NOTATKA} znaków.",
        })
    analiza.notatka = tresc
    analiza.save(update_fields=["notatka"])
    Zdarzenie.objects.create(uzytkownik=request.user, analiza=analiza, typ="notatka")
    return render(request, "analizy/_opcje.html", {"analiza": analiza, "zapisano": True})


@login_required
@require_POST
def usun(request, pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    # zdarzenie bez powiązania — analiza (i jej zdarzenia) znika z bazy
    Zdarzenie.objects.create(uzytkownik=request.user, typ="usuniecie", szczegoly={
        "plik": analiza.nazwa_pliku, "sha256": analiza.sha256, "ticket_id": analiza.ticket_id,
        "utworzono": analiza.utworzono.isoformat(),
    })
    analiza.delete()
    return redirect("analizy:lista")


@login_required
def szczegoly_ioc(request, pk, ioc_pk):
    analiza = get_object_or_404(Analiza, pk=pk)
    ioc = get_object_or_404(analiza.ioc, pk=ioc_pk)
    wzbogacenia, _ = prezentacja.widoki_wzbogacen(analiza)
    return render(request, "analizy/_szczegoly_ioc.html", {"i": ioc, "wz": wzbogacenia[ioc.pk], "analiza": analiza})


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
    odpowiedz = HttpResponse(SZABLON_PODGLADU.replace("{tresc}", ponownie_oczysc(w.get("html_bezpieczny") or "")))
    odpowiedz["Content-Security-Policy"] = CSP_PODGLADU
    odpowiedz["X-Content-Type-Options"] = "nosniff"
    odpowiedz["Referrer-Policy"] = "no-referrer"
    return odpowiedz
