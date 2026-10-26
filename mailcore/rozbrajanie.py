"""Rozbrajanie IOC do wyświetlania: hxxp, [.] — żeby nic nie dało się przypadkiem kliknąć."""

import re


def _kropki(tekst: str) -> str:
    return tekst.replace(".", "[.]")


def rozbroj(typ: str, wartosc: str) -> str:
    if typ == "url":
        znaleziony = re.match(r"(?i)(https?)(://)([^/?#]*)(.*)", wartosc, re.DOTALL)
        if not znaleziony:
            return _kropki(wartosc)
        schemat, sep, host, reszta = znaleziony.groups()
        return "hxxp" + schemat[4:].lower() + sep + _kropki(host) + reszta
    if typ == "email":
        lokalna, _, domena = wartosc.rpartition("@")
        return f"{lokalna}@{_kropki(domena)}" if lokalna else _kropki(wartosc)
    if typ in ("domena", "ip"):
        return _kropki(wartosc)
    return wartosc
