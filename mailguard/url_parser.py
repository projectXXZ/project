import re
from bs4 import BeautifulSoup

from .my_types import LinkFound


URL_RE = re.compile(r"https?://[^\s<>\"']+", flags=re.IGNORECASE)


def _normalize_url(url: str) -> str:
    return (url or "").strip().rstrip(").,]>'\"")


def extract_all_urls(text: str, html: str) -> list[LinkFound]:
    out: list[LinkFound] = []

    for m in URL_RE.finditer(text or ""):
        u = _normalize_url(m.group(0))
        if u:
            out.append(LinkFound(u, "text"))

    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
            for a in soup.find_all("a"):
                href = a.get("href")
                if not href:
                    continue
                href = _normalize_url(str(href))
                if not href:
                    continue
                if href.lower().startswith("http://") or href.lower().startswith("https://"):
                    out.append(LinkFound(href, "html_href", a.get_text(" ", strip=True) or None))
        except Exception:
            pass

    return dedupe_links(out)


def dedupe_links(links: list[LinkFound]) -> list[LinkFound]:
    seen = set()
    uniq: list[LinkFound] = []
    for l in links:
        u = _normalize_url(l.url)
        if not u or u in seen:
            continue
        seen.add(u)
        uniq.append(LinkFound(u, l.source, l.visible_text))
    return uniq
