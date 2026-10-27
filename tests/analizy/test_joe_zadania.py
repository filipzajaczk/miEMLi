import json
import logging
from datetime import timedelta

import pytest
from django.utils import timezone

from analizy import joe_zadania as jz
from analizy.klucze_joe import nowa_para, zaszyfruj_klucz
from analizy.models import Analiza, ZgloszenieJoe, Zdarzenie, profil_dla
from analizy.uslugi import utworz_lub_otworz
from integracje import joe
from integracje.joe import WynikJoe

pytestmark = pytest.mark.django_db
KLUCZ = "KluczJoeAnalityka1234567890"


@pytest.fixture(autouse=True)
def para(settings):
    settings.JOE_KLUCZ_PUBLICZNY, settings.JOE_KLUCZ_PRYWATNY = nowa_para()
    settings.JOE_LIMIT_DZIENNY = 20


@pytest.fixture
def kolejka(monkeypatch):
    wywolania = []
    monkeypatch.setattr(jz, "_kolejkuj",
                        lambda f, *a, opoznienie=0: wywolania.append((f.__name__, a, opoznienie)) or True)
    return wywolania


@pytest.fixture
def z_kluczem(analityk):
    p = profil_dla(analityk)
    p.joe_klucz_szyfr = zaszyfruj_klucz(analityk.pk, KLUCZ)
    p.joe_klucz_koncowka = KLUCZ[-4:]
    p.save()
    return analityk


@pytest.fixture
def analiza(probka, analityk):
    return utworz_lub_otworz(probka("phishing_klasyczny"), "Faktura_tajna.eml", analityk)[0]


@pytest.fixture
def joe_atrapa(monkeypatch):
    stan = {"wyslij": WynikJoe("ok", {"id_zgloszenia": "77"}), "stan": [], "info": WynikJoe("ok"), "wywolania": []}

    def wyslij(klucz, dane, nazwa, komentarz, baza=None):
        stan["wywolania"].append(("wyslij", klucz, nazwa, komentarz, len(dane)))
        return stan["wyslij"]

    def stan_zgl(klucz, id_zgl, baza=None):
        stan["wywolania"].append(("stan", id_zgl))
        return stan["stan"].pop(0)

    def info(klucz, baza=None):
        stan["wywolania"].append(("info",))
        return stan["info"]

    monkeypatch.setattr(joe, "wyslij", wyslij)
    monkeypatch.setattr(joe, "stan_zgloszenia", stan_zgl)
    monkeypatch.setattr(joe, "info_konta", info)
    return stan


def zlec(analiza, uzytkownik, dane, capture):
    with capture(execute=True):
        return jz.zlec_wysylke(analiza, uzytkownik, dane)


def test_zlecenie_ok(analiza, z_kluczem, kolejka, probka, django_capture_on_commit_callbacks):
    z = zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    assert z.status == "zlecone"
    assert Zdarzenie.objects.filter(typ="joe_wyslanie", analiza=analiza).exists()
    assert kolejka[0][0] == "wyslij_do_joe" and kolejka[0][1][0] == z.pk


def test_kolejka_tylko_szyfrogram(analiza, z_kluczem, kolejka, probka, django_capture_on_commit_callbacks):
    zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    argumenty = json.dumps(kolejka[0][1])
    assert "Zaległa" not in argumenty and "pko-platnosci" not in argumenty and "From:" not in argumenty


@pytest.mark.parametrize("zmiana", [lambda d: b"inny mail", lambda d: d + b"\n"])
def test_inny_plik(analiza, z_kluczem, kolejka, probka, zmiana):
    with pytest.raises(jz.BladZlecenia, match="To nie jest ten sam plik co w analizie."):
        jz.zlec_wysylke(analiza, z_kluczem, zmiana(probka("phishing_klasyczny")))
    assert kolejka == [] and not ZgloszenieJoe.objects.exists()


def test_brak_klucza(analiza, analityk, kolejka, probka):
    with pytest.raises(jz.BladZlecenia, match="Ustaw klucz Joe w profilu."):
        jz.zlec_wysylke(analiza, analityk, probka("phishing_klasyczny"))


def test_duplikat_10_min(analiza, z_kluczem, kolejka, probka, django_capture_on_commit_callbacks):
    zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    with pytest.raises(jz.BladZlecenia, match="Już wysłano — poczekaj na wynik."):
        jz.zlec_wysylke(analiza, z_kluczem, probka("phishing_klasyczny"))
    ZgloszenieJoe.objects.update(utworzono=timezone.now() - timedelta(minutes=11))
    zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    assert ZgloszenieJoe.objects.count() == 2


def test_limit_dzienny(analiza, z_kluczem, kolejka, probka, settings, django_capture_on_commit_callbacks):
    settings.JOE_LIMIT_DZIENNY = 2
    for _ in range(2):
        zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
        ZgloszenieJoe.objects.update(utworzono=timezone.now() - timedelta(minutes=11))
    ZgloszenieJoe.objects.update(utworzono=timezone.localtime().replace(hour=0, minute=1))
    with pytest.raises(jz.BladZlecenia, match="Osiągnięto dzienny limit wysyłek do Joe."):
        jz.zlec_wysylke(analiza, z_kluczem, probka("phishing_klasyczny"))


@pytest.fixture
def zgloszenie(analiza, z_kluczem, kolejka, probka, django_capture_on_commit_callbacks):
    z = zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    szyfrogram = kolejka[0][1][1]
    kolejka.clear()
    return z, szyfrogram


def test_wysylka_ok_i_sledzenie(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    jz.wyslij_do_joe(z.pk, szyfrogram)
    z.refresh_from_db()
    assert z.status == "wyslane" and z.id_zgloszenia == "77" and z.wyslano
    assert joe_atrapa["wywolania"][0][1] == KLUCZ and joe_atrapa["wywolania"][0][2] == f"analiza-{z.analiza_id}.eml"
    assert joe_atrapa["wywolania"][0][3] == f"miemli, analiza #{z.analiza_id}"
    assert kolejka == [("sprawdz_joe", (z.pk,), 30)]
    kolejka.clear()
    joe_atrapa["stan"] = [WynikJoe("ok", {"status": "trwa", "webid": "4521", "werdykt": None, "wynik": None}),
                          WynikJoe("ok", {"status": "zakonczone", "webid": "4521", "werdykt": "zlosliwy", "wynik": 87})]
    jz.sprawdz_joe(z.pk)
    z.refresh_from_db()
    assert z.status == "trwa" and z.link == "https://jbxcloud.joesecurity.org/analysis/4521"
    assert kolejka == [("sprawdz_joe", (z.pk,), 30)]
    kolejka.clear()
    jz.sprawdz_joe(z.pk)
    z.refresh_from_db()
    assert (z.status, z.werdykt, z.wynik) == ("zakonczone", "zlosliwy", 87) and kolejka == []


def test_ponowienia_limit(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    joe_atrapa["wyslij"] = WynikJoe("limit", blad="Wyczerpany limit Joe.", ponawiac=True)
    jz.wyslij_do_joe(z.pk, szyfrogram, 0)
    jz.wyslij_do_joe(z.pk, szyfrogram, 1)
    assert [k[2] for k in kolejka] == [60, 300] and kolejka[0][1] == (z.pk, szyfrogram, 1)
    jz.wyslij_do_joe(z.pk, szyfrogram, 2)
    z.refresh_from_db()
    assert z.status == "limit" and z.blad == "Wyczerpany limit Joe."


def test_niedostepny_ponowienia(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    joe_atrapa["wyslij"] = WynikJoe("niedostepny", blad="Joe niedostępny.", ponawiac=True)
    jz.wyslij_do_joe(z.pk, szyfrogram, 0)
    jz.wyslij_do_joe(z.pk, szyfrogram, 1)
    assert [k[2] for k in kolejka] == [30, 120]


def test_odrzucony_klucz(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    joe_atrapa["wyslij"] = WynikJoe("odrzucony", blad="Klucz Joe odrzucony — sprawdź go w profilu.")
    jz.wyslij_do_joe(z.pk, szyfrogram)
    z.refresh_from_db()
    assert z.status == "blad" and z.blad == "Klucz Joe odrzucony — sprawdź go w profilu." and kolejka == []


def test_klucz_usuniety_w_trakcie(zgloszenie, z_kluczem, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    profil_dla(z_kluczem).__class__.objects.filter(uzytkownik=z_kluczem).update(joe_klucz_szyfr=None)
    jz.wyslij_do_joe(z.pk, szyfrogram)
    z.refresh_from_db()
    assert z.status == "blad" and z.blad == "Ustaw ponownie klucz Joe w profilu." and joe_atrapa["wywolania"] == []


def test_zla_para_kluczy(zgloszenie, z_kluczem, kolejka, joe_atrapa, settings):
    z, szyfrogram = zgloszenie
    settings.JOE_KLUCZ_PUBLICZNY, settings.JOE_KLUCZ_PRYWATNY = nowa_para()
    jz.wyslij_do_joe(z.pk, szyfrogram)
    z.refresh_from_db()
    assert z.status == "blad" and joe_atrapa["wywolania"] == []


def test_analiza_usunieta_w_trakcie(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    Analiza.objects.all().delete()
    jz.wyslij_do_joe(z.pk, szyfrogram)
    jz.sprawdz_joe(z.pk)
    assert joe_atrapa["wywolania"] == [] and kolejka == []


def test_czas_minal(zgloszenie, kolejka, joe_atrapa):
    z, _ = zgloszenie
    ZgloszenieJoe.objects.filter(pk=z.pk).update(status="trwa", id_zgloszenia="77",
                                                  wyslano=timezone.now() - timedelta(hours=2, minutes=1))
    joe_atrapa["stan"] = [WynikJoe("ok", {"status": "trwa", "webid": "1", "werdykt": None, "wynik": None})]
    jz.sprawdz_joe(z.pk)
    z.refresh_from_db()
    assert z.status == "czas_minal" and kolejka == []


def test_sprawdz_klucz(z_kluczem, joe_atrapa):
    jz.sprawdz_klucz_joe(z_kluczem.pk)
    assert profil_dla(z_kluczem).joe_klucz_stan == "dziala"
    joe_atrapa["info"] = WynikJoe("odrzucony", blad="x")
    jz.sprawdz_klucz_joe(z_kluczem.pk)
    assert profil_dla(z_kluczem).joe_klucz_stan == "odrzucony"


def test_logi_bez_klucza_i_nazwy(zgloszenie, kolejka, joe_atrapa, caplog):
    caplog.set_level(logging.DEBUG)
    z, szyfrogram = zgloszenie
    jz.wyslij_do_joe(z.pk, szyfrogram)
    assert KLUCZ not in caplog.text and "Faktura_tajna" not in caplog.text


# --- z końcowego przeglądu ---

def test_kolejka_niedostepna_oznacza_blad(analiza, z_kluczem, probka, monkeypatch, django_capture_on_commit_callbacks):
    monkeypatch.setattr(jz, "_kolejkuj", lambda *a, **kw: False)
    z = zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    z.refresh_from_db()
    assert z.status == "blad" and "Kolejka" in z.blad


@pytest.mark.parametrize("wyjatek", [RuntimeError("x"), ValueError("y")])
def test_nieoczekiwany_wyjatek_w_wysylce(zgloszenie, kolejka, monkeypatch, wyjatek):
    z, szyfrogram = zgloszenie

    def pada(*a, **kw):
        raise wyjatek

    monkeypatch.setattr(joe, "wyslij", pada)
    jz.wyslij_do_joe(z.pk, szyfrogram)
    z.refresh_from_db()
    assert z.status == "blad" and z.blad == "Błąd wewnętrzny wysyłki."


def test_nieoczekiwany_wyjatek_w_sledzeniu(zgloszenie, kolejka, monkeypatch):
    z, _ = zgloszenie
    ZgloszenieJoe.objects.filter(pk=z.pk).update(status="trwa", id_zgloszenia="77", wyslano=timezone.now())

    def pada(*a, **kw):
        raise RuntimeError("x")

    monkeypatch.setattr(joe, "stan_zgloszenia", pada)
    jz.sprawdz_joe(z.pk)
    z.refresh_from_db()
    assert z.status == "blad"


def test_powtorzone_zadanie_nie_wysyla_drugi_raz(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    jz.wyslij_do_joe(z.pk, szyfrogram)
    jz.wyslij_do_joe(z.pk, szyfrogram)
    assert [w[0] for w in joe_atrapa["wywolania"]].count("wyslij") == 1


def test_ponowienie_wraca_do_zlecone(zgloszenie, kolejka, joe_atrapa):
    z, szyfrogram = zgloszenie
    joe_atrapa["wyslij"] = WynikJoe("limit", blad="Wyczerpany limit Joe.", ponawiac=True)
    jz.wyslij_do_joe(z.pk, szyfrogram, 0)
    z.refresh_from_db()
    assert z.status == "zlecone"
    joe_atrapa["wyslij"] = WynikJoe("ok", {"id_zgloszenia": "9"})
    jz.wyslij_do_joe(z.pk, szyfrogram, 1)
    z.refresh_from_db()
    assert z.status == "wyslane"


def test_bledne_zgloszenie_nie_blokuje_ponowienia(analiza, z_kluczem, kolejka, probka, django_capture_on_commit_callbacks):
    z = zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    ZgloszenieJoe.objects.filter(pk=z.pk).update(status="blad")
    zlec(analiza, z_kluczem, probka("phishing_klasyczny"), django_capture_on_commit_callbacks)
    assert ZgloszenieJoe.objects.count() == 2


def test_joe_nieskonfigurowany(analiza, z_kluczem, probka, settings):
    settings.JOE_KLUCZ_PUBLICZNY = ""
    with pytest.raises(jz.BladZlecenia, match="Integracja z Joe Sandbox nie jest skonfigurowana."):
        jz.zlec_wysylke(analiza, z_kluczem, probka("phishing_klasyczny"))


def test_brak_klucza_prywatnego_w_workerze_nie_psuje_kluczy(zgloszenie, z_kluczem, kolejka, joe_atrapa, settings, caplog):
    z, szyfrogram = zgloszenie
    settings.JOE_KLUCZ_PRYWATNY = ""
    jz.wyslij_do_joe(z.pk, szyfrogram)
    jz.sprawdz_klucz_joe(z_kluczem.pk)
    z.refresh_from_db()
    assert z.status == "blad" and profil_dla(z_kluczem).joe_klucz_stan != "odrzucony"
    assert any(r.levelno >= logging.ERROR for r in caplog.records)


def test_wiszace_zgloszenie_wygasa_w_widoku(analiza, analityk):
    from analizy.views import _kontekst_joe

    z = ZgloszenieJoe.objects.create(analiza=analiza, uzytkownik=analityk, status="zlecone")
    ZgloszenieJoe.objects.filter(pk=z.pk).update(utworzono=timezone.now() - timedelta(hours=3))

    class Zadanie:
        user = analityk
        session = {}

    kontekst = _kontekst_joe(Zadanie(), analiza)
    z.refresh_from_db()
    assert z.status == "czas_minal" and kontekst["joe_trwa"] is False
