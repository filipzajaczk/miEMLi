"""Pomocnicze operacje na tekście wiadomości."""

from bs4 import BeautifulSoup


def tekst_z_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for zbedne in soup(["script", "style", "head"]):
        zbedne.decompose()
    return soup.get_text(" ")
