"""HTML wiadomości do podglądu: bez skryptów, bez zewnętrznych zasobów, bez klikalnych linków.

To pierwsza warstwa. Druga to iframe sandbox + CSP `default-src 'none'; img-src data:` w widoku.
"""

import base64

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
USUWANE_Z_TRESCIA = {"script", "style", "head", "title", "form", "iframe", "object", "embed", "noscript", "template", "svg", "math"}


def bezpieczny_html(html: str, zalaczniki: list[Zalacznik], obrazy: dict[str, bytes | str] | None = None) -> str:
    """obrazy: content_id → przekodowany PNG albo powód pominięcia. Oryginalne bajty obrazków z maila
    nigdy nie trafiają do wyniku — brak wpisu oznacza obrazek pominięty."""
    obrazy = obrazy or {}
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["meta", "base", "link"]):
        tag.decompose()

    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        a.name = "span"
        a.attrs = {"class": "link"}
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
            else:
                tag.attrs.pop("src", None)
        else:
            tag.attrs.pop("src", None)

    return ponownie_oczysc(str(soup))


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
    )
