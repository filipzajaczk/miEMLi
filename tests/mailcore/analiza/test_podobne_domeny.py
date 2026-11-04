import pytest

from mailcore.analiza import analizuj
from mailcore.analiza.linki import Link
from mailcore.analiza.podobne_domeny import MAKS_WZORCOW, wykryj_podobne_domeny
from mailcore.model import Wiadomosc
from mailcore.parsuj import parsuj

FIRMA = frozenset()


def wiadomosc(naglowki):
    return Wiadomosc("0", naglowki, None, None, [], None, None, None, [], [])


def link(url):
    return Link(url, url, None, False, "html")


def sygnaly(od, do="m.zaczek@zwik.pl", firma=FIRMA, linki=(), **dodatkowe):
    naglowki = [("From", od), ("To", do)]
    naglowki += [(k.replace("_", "-"), v) for k, v in dodatkowe.items()]
    return wykryj_podobne_domeny(wiadomosc(naglowki), list(linki), firma)


def test_przypadek_ze_zgloszenia():
    wynik = sygnaly("zlocieniec@zwlk.pl", Return_Path="<zlocieniec@zwlk.pl>")
    assert [s.kod for s in wynik] == ["DOMENA_PODOBNA"]
    assert all(f in wynik[0].opis for f in ("zwlk.pl", "zwik.pl", "From", "Return-Path", "„l” zamiast „i”"))


@pytest.mark.parametrize("nadawca, wzorzec", [
    ("zwlk.pl", "zwik.pl"),            # podmiana
    ("zwiik.pl", "zwik.pl"),           # wstawienie
    ("zik.pl", "zwik.pl"),             # usunięcie
    ("zwki.pl", "zwik.pl"),            # zamiana sąsiednich liter
    ("pocztaa-firmowo.pl", "poczta-firmowa.pl"),  # dwie zmiany w długiej nazwie
    ("rnbank.pl", "mbank.pl"),         # rn/m
    ("vvodociagi.pl", "wodociagi.pl"), # vv/w
    ("g00gle.pl", "google.pl"),        # 0/o
    ("zwik.com", "zwik.pl"),           # inna końcówka
    ("zwik.com.pl", "zwik.pl"),        # końcówka drugiego poziomu
    ("zwіk.pl", "zwik.pl"),            # cyrylickie „і”
    ("xn--zwk-khd.pl", "zwik.pl"),     # to samo w punycode
    ("zwík.pl", "zwik.pl"),            # znak diakrytyczny
    ("ZWLK.PL", "zwik.pl"),            # wielkość liter
])
def test_wykrywa(nadawca, wzorzec):
    assert sygnaly(f"a@{nadawca}", f"b@{wzorzec}")


@pytest.mark.parametrize("nadawca, wzorzec", [
    ("zwik.pl", "zwik.pl"),            # ta sama domena
    ("poczta.zwik.pl", "zwik.pl"),     # subdomena
    ("zwik.pl", "poczta.zwik.pl"),     # odbiorca w subdomenie
    ("zupelnie-inna.pl", "zwik.pl"),   # nic wspólnego
    ("zwax.pl", "zwik.pl"),            # dwie zmiany w krótkiej nazwie
    ("abc.pl", "abd.pl"),              # zbyt krótka nazwa
    ("wp.pl", "o2.pl"),                # zbyt krótka nazwa
    ("gmail.com", "googlemail.com"),   # znane darmowe skrzynki
    ("hotmail.com", "outlook.com"),
])
def test_nie_wykrywa(nadawca, wzorzec):
    assert sygnaly(f"a@{nadawca}", f"b@{wzorzec}") == []



@pytest.mark.parametrize("naglowek", ["Reply_To", "Return_Path"])
def test_sprawdza_kolejne_naglowki_nadawcy(naglowek):
    wynik = sygnaly("a@neutralna-domena.pl", **{naglowek: "x@zwlk.pl"})
    assert len(wynik) == 1 and naglowek.replace("_", "-") in wynik[0].opis


def test_link_do_domeny_podobnej():
    wynik = sygnaly("a@neutralna-domena.pl", linki=[link("https://logowanie.zwlk.pl/x")])
    assert len(wynik) == 1 and "link" in wynik[0].opis and "zwlk.pl" in wynik[0].opis


def test_link_z_ip_i_uszkodzony_bez_bledu():
    linki = [link("http://192.168.100.200/x"), link("http://[::1]/x"), link("http://[zepsuty/x")]
    assert sygnaly("a@neutralna-domena.pl", linki=linki) == []


def test_jeden_sygnal_na_podejrzana_domene():
    wynik = sygnaly("a@zwlk.pl", Reply_To="b@zwlk.pl", linki=[link("https://zwlk.pl/"), link("https://www.zwlk.pl/2")])
    assert len(wynik) == 1
    assert all(f in wynik[0].opis for f in ("From", "Reply-To", "link"))


def test_kazda_podejrzana_domena_osobno():
    assert len(sygnaly("a@zwlk.pl", Reply_To="b@zwiik.pl")) == 2


def test_odbiorca_w_kopii():
    assert sygnaly("a@zwlk.pl", "x@neutralna-domena.pl", Cc="b@zwik.pl")


def test_odbiorcy_rozdzieleni_srednikiem_jak_w_msg():
    assert sygnaly("a@zwlk.pl", "Ktoś <x@neutralna-domena.pl>; Inny <b@zwik.pl>")


def test_domena_firmy_jako_wzorzec():
    wynik = sygnaly("a@zwlk.pl", "prywatny@neutralna-domena.pl", firma=frozenset({"zwik.pl"}))
    assert len(wynik) == 1 and "firmy" in wynik[0].opis


def test_domena_firmy_nie_jest_podejrzana():
    assert sygnaly("a@zwik.pl", "partner@zwig.pl", firma=frozenset({"zwik.pl"})) == []


def test_napastnik_nie_ukryje_sie_dopisujac_sie_do_odbiorcow():
    assert sygnaly("a@zwlk.pl", "b@zwik.pl, c@zwlk.pl")


def test_domena_firmy_ma_pierwszenstwo_przy_limicie_odbiorcow():
    do = ", ".join(f"x@odbiorca-numer-{i}.pl" for i in range(MAKS_WZORCOW * 2))
    assert sygnaly("a@zwlk.pl", do, firma=frozenset({"zwik.pl"}))


def test_bardzo_dluga_nazwa_jest_pomijana():
    dluga = "a" * 5000
    assert sygnaly(f"a@{dluga}b.pl", f"b@{dluga}.pl") == []


def test_uszkodzony_punycode_bez_bledu():
    assert sygnaly("a@xn--a.pl", "b@zwik.pl") == []


def test_brak_naglowkow():
    assert wykryj_podobne_domeny(wiadomosc([]), [], FIRMA) == []


def test_analizuj_laczy_linki_i_domeny_firmy(zbuduj_mail):
    w = parsuj(zbuduj_mail(od="a@neutralna-domena.pl", do="b@inna-neutralna.pl",
                           html='<a href="https://zwlk.pl/">x</a>'), "a.eml")
    bez = analizuj(w).wiadomosci["0"].sygnaly
    z_firma = analizuj(w, frozenset({"zwik.pl"})).wiadomosci["0"].sygnaly
    assert "DOMENA_PODOBNA" not in [s.kod for s in bez]
    assert "DOMENA_PODOBNA" in [s.kod for s in z_firma]


def test_analizuj_zagniezdzona_wiadomosc_ma_wlasny_sygnal(zbuduj_mail):
    wewn = zbuduj_mail(od="a@zwlk.pl", do="b@zwik.pl", tekst="x")
    w = parsuj(zbuduj_mail(od="c@neutralna-domena.pl", do="soc@inna-neutralna.pl", tekst="fw",
                           zagniezdzone=[wewn]), "a.eml")
    wiadomosci = analizuj(w).wiadomosci
    assert "DOMENA_PODOBNA" not in [s.kod for s in wiadomosci["0"].sygnaly]
    assert any("DOMENA_PODOBNA" in [s.kod for s in a.sygnaly] for a in wiadomosci.values())
