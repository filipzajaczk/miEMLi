"""Censys Platform API v3 — dane hosta (porty, usługi, ASN, lokalizacja)."""

import httpx

from .wspolne import WynikDostawcy, nowy_klient, wykonaj

BAZA = "https://api.platform.censys.io/v3/global/asset/host"
GUI = "https://platform.censys.io/hosts"


def skrot_censys(odpowiedz: dict) -> dict:
    r = odpowiedz["result"]["resource"]
    uslugi = sorted(
        ([s.get("port"), s.get("protocol"), s.get("transport_protocol")] for s in r.get("services") or []),
        key=lambda u: (u[0] is None, u[0] or 0),
    )
    asys = r.get("autonomous_system") or {}
    lok = r.get("location") or {}
    return {
        "uslugi": uslugi,
        "asn": asys.get("asn"),
        "as_nazwa": asys.get("name"),
        "bgp": asys.get("bgp_prefix"),
        "kraj": lok.get("country_code"),
        "miasto": lok.get("city"),
        "dns": list((r.get("dns") or {}).get("names") or [])[:10],
    }


class KlientCensys:
    def __init__(self, token: str, organizacja: str = "", klient: httpx.Client | None = None):
        self.token = token
        self.organizacja = organizacja
        self.klient = klient

    def sprawdz_ip(self, ip: str) -> WynikDostawcy:
        naglowki = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        params = {"organization_id": self.organizacja} if self.organizacja else None
        argumenty = (f"{BAZA}/{ip}", naglowki, skrot_censys, f"{GUI}/{ip}", params)
        if self.klient is not None:
            return wykonaj(self.klient, *argumenty)
        with nowy_klient() as klient:
            return wykonaj(klient, *argumenty)
