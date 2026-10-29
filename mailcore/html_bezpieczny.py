"""HTML wiadomości do podglądu: bez skryptów, bez zewnętrznych zasobów, bez klikalnych linków.

To pierwsza warstwa. Druga to iframe sandbox + CSP `default-src 'none'; img-src data:` w widoku.
"""

import base64
import re
from urllib.parse import urlsplit

import nh3
from bs4 import BeautifulSoup

from .analiza.linki import rozpakuj_przekierowanie
from .model import Zalacznik
from .rozbrajanie import rozbroj

TAGI = {
    "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col", "colgroup", "dd", "del",
    "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "li",
    "ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody",
    "td", "tfoot", "th", "thead", "tr", "u", "ul",
}
ATRYBUTY_WSPOLNE = {"style", "title", "class", "align", "width", "height", "colspan", "rowspan", "valign", "bgcolor", "color"}
ATRYBUTY = {"*": ATRYBUTY_WSPOLNE, "img": {"src", "alt"}}
# Bez background/background-image/list-style-image itp. — tylko właściwości bez URL-i
STYLE = {
    "color", "background-color", "font", "font-family", "font-size", "font-style", "font-weight",
    "text-align", "text-decoration", "text-indent", "text-transform", "line-height", "letter-spacing",
    "white-space", "vertical-align", "display", "width", "max-width", "min-width", "height",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "border", "border-top", "border-right", "border-bottom", "border-left", "border-color",
    "border-width", "border-style", "border-collapse", "border-spacing", "border-radius",
}
KLASY_ZASTRZEZONE = {"link", "obraz-zewnetrzny", "obrazek-pominiety"}
_HOST = re.compile(r"[a-z0-9.-]{1,253}|[0-9a-f:.]{2,45}")
USUWANE_Z_TRESCIA = {"script", "style", "head", "title", "form", "iframe", "object", "embed", "noscript", "template", "svg", "math"}


def bezpieczny_html(html: str, zalaczniki: list[Zalacznik], obrazy: dict[str, bytes | str] | None = None) -> str:
    """obrazy: content_id → przekodowany PNG albo powód pominięcia. Oryginalne bajty obrazków z maila
    nigdy nie trafiają do wyniku — brak wpisu oznacza obrazek pominięty."""
    obrazy = obrazy or {}
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["meta", "base", "link"]):
        tag.decompose()

    # Dymki i klasy zastępników nadaje wyłącznie sanitizer — mail nie może ich podrobić
    for tag in soup.find_all(True):
        tag.attrs.pop("title", None)
        klasy = [k for k in tag.get("class") or [] if k not in KLASY_ZASTRZEZONE]
        if klasy:
            tag["class"] = klasy
        else:
            tag.attrs.pop("class", None)

    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        styl = a.get("style")
        a.name = "span"
        # styl zostaje (przyciski wyglądają jak u ofiary) — filtruje go allowlista właściwości nh3
        a.attrs = {"class": "link", **({"style": styl} if styl else {})}
        if href.lower().startswith(("http://", "https://")):
            a["title"] = rozbroj("url", rozpakuj_przekierowanie(href) or href)

    for tag in soup.find_all(True):
        for atrybut in ("srcset", "background", "poster", "lowsrc", "dynsrc"):
            tag.attrs.pop(atrybut, None)
        if tag.name == "img":
            src = (tag.get("src") or "").strip()
            if src.lower().startswith("cid:"):
                obraz = obrazy.get(src[4:].strip("<>"))
                if isinstance(obraz, bytes):
                    tag["src"] = f"data:image/png;base64,{base64.b64encode(obraz).decode('ascii')}"
                else:
                    powod = f": {obraz}" if obraz else ""
                    zastepczy = soup.new_tag("span", attrs={"class": "obrazek-pominiety"})
                    zastepczy.string = f"[obrazek pominięty{powod}]"
                    tag.replace_with(zastepczy)
            elif src.lower().startswith(("http://", "https://")):
                # tylko host: ścieżka i parametry bywają identyfikatorem ofiary (piksel śledzący)
                host = _host_zewnetrzny(src)
                zastepczy = soup.new_tag("span", attrs={"class": "obraz-zewnetrzny"})
                zastepczy.string = f"[obraz zewnętrzny: {rozbroj('domena', host)}]" if host else "[obraz zewnętrzny]"
                tag.replace_with(zastepczy)
            else:
                tag.attrs.pop("src", None)
        else:
            tag.attrs.pop("src", None)

    return ponownie_oczysc(str(soup))


def _host_zewnetrzny(src: str) -> str | None:
    """Host w postaci ASCII (punycode — homoglify widoczne), albo None, gdy nie wygląda na domenę/IP:
    tekst ramki nie może być dowolnym napisem atakującego."""
    try:
        host = urlsplit(src).hostname or ""
        host = host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return None
    return host if _HOST.fullmatch(host) else None


def ponownie_oczysc(html: str) -> str:
    """Sama allowlista nh3 — także przy wyświetlaniu HTML zapisanego wcześniej w bazie
    (poprawka sanitizera obejmuje wtedy również stare analizy)."""
    return nh3.clean(
        html,
        tags=TAGI,
        clean_content_tags=USUWANE_Z_TRESCIA,
        attributes=ATRYBUTY,
        url_schemes={"data"},
        filter_style_properties=STYLE,
        link_rel=None,
        attribute_filter=_tylko_png,
    )


def _tylko_png(tag: str, atrybut: str, wartosc: str) -> str | None:
    """Do przeglądarki trafiają wyłącznie obrazki PNG wygenerowane przez sandbox — żadnych innych data: URI
    (np. WebP/SVG/HTML), nawet gdyby przejęty parser je podsunął."""
    if tag == "img" and atrybut == "src":
        return wartosc if wartosc.startswith("data:image/png;base64,") else None
    return wartosc
