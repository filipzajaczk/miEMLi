"""Porównywanie domen bez pełnej listy Public Suffix — wystarczające dla sygnałów podszywania."""

# Popularne sufiksy drugiego poziomu (domena bazowa ma wtedy trzy etykiety)
SUFIKSY_2_POZIOMU = frozenset({
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "info.pl", "biz.pl", "waw.pl", "mil.pl",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "com.cn",
    "co.in", "co.za", "com.tr", "com.ua", "com.ru",
})


def normalizuj(host: str) -> str:
    return host.strip().strip(".").lower()


def domena_bazowa(host: str) -> str:
    etykiety = normalizuj(host).split(".")
    if len(etykiety) >= 3 and ".".join(etykiety[-2:]) in SUFIKSY_2_POZIOMU:
        return ".".join(etykiety[-3:])
    return ".".join(etykiety[-2:])


def domena_adresu(adres: str | None) -> str | None:
    if not adres or "@" not in adres:
        return None
    return normalizuj(adres.rsplit("@", 1)[1]) or None
