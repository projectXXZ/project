import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlparse

import ipaddress
import tldextract
from rapidfuzz.distance import Levenshtein

from .my_types import LinkFound, CheckedURL
from .brand_domains import BRAND_DOMAINS
from .shortener_domains import SHORTENER_DOMAINS
from .net import safe_head_then_get
from .dns_tools import ns_records
from .rdap_tools import domain_age_days
from .tls_tools import tls_info, cert_age_days
from .threat_intel import virustotal_url_report, urlhaus_url_info


_TLDX = tldextract.TLDExtract(suffix_list_urls=None)

DANGER_TLDS = {
    ".shop",
    ".top",
    ".xyz",
    ".icu",
    ".click",
    ".win",
    ".zip",
    ".bid",
    ".gift",
    ".cfd",
    ".live",
    ".buzz",
    ".rest",
    ".surf",
    ".monster",
    ".sbs",
}
SAFE_PLATFORM_DOMAINS = {
    "t.me",
    "telegram.me",
    "telegram.org",
    "wa.me",
    "whatsapp.com",
    "vk.com",
    "ok.ru",
    "instagram.com",
    "facebook.com",
    "messenger.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "discord.gg",
    "discord.com",
}

UNSUB_TOKENS = ("unsub", "unsubscribe", "unsubscriptions", "optout", "opt-out")


def _tld(host: str):
    h = (host or "").strip().lower()
    if not h:
        return None
    try:
        return _TLDX(h)
    except TypeError:
        try:
            extract = getattr(_TLDX, "extract", None)
            return extract(h) if callable(extract) else None
        except Exception:
            return None
    except Exception:
        return None


def _registered_domain(host: str) -> str:
    ext = _tld(host)
    if not ext:
        return ""
    try:
        suf = getattr(ext, "suffix", "") or ""
        dom = getattr(ext, "domain", "") or ""
        if suf:
            return f"{dom}.{suf}".lower()
        return dom.lower()
    except Exception:
        return ""


def _host_of(url: str) -> str:
    try:
        p = urlparse(url)
        return (p.hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _domain_of(url: str) -> str:
    try:
        return _registered_domain(_host_of(url))
    except Exception:
        return ""


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _idn_flags(host: str) -> list[str]:
    flags: list[str] = []
    try:
        if not host:
            return flags
        any_non_ascii = any(ord(ch) > 127 for ch in host)
        any_ascii_alpha = any(("a" <= ch <= "z") or ("A" <= ch <= "Z") for ch in host)
        if "xn--" in host:
            flags.append("idn_punycode")
        if any_non_ascii:
            flags.append("non_ascii_domain")
            if any_ascii_alpha:
                flags.append("mixed_script_domain")
    except Exception:
        return flags
    return flags


_PHISHY_PATH_RE = re.compile(
    r"(?:/|\b)(login|signin|verify|update|secure|account|bank|wallet|support|confirm|password|2fa|otp|bonus|prize|win)(?:\b|/|\?|=)",
    flags=re.IGNORECASE,
)


def _path_token_flags(url: str) -> list[str]:
    flags: list[str] = []
    try:
        p = urlparse(url)
        path = (p.path or "") + " " + (p.query or "")
        if _PHISHY_PATH_RE.search(path):
            flags.append("phishy_path")
    except Exception:
        pass
    return flags


def _extract_domain_from_text(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    if len(t) > 120:
        return ""
    if re.fullmatch(r"https?://\S+", t, flags=re.IGNORECASE):
        return _domain_of(t)
    if re.fullmatch(r"([a-z0-9][a-z0-9\-]{0,62}\.)+[a-z]{2,}", t, flags=re.IGNORECASE):
        return _registered_domain(t)
    return ""


def _visible_text_mismatch(link: LinkFound, domain: str) -> bool:
    if not link.visible_text:
        return False
    vd = _extract_domain_from_text(link.visible_text)
    if not vd or not domain:
        return False
    return vd != domain


def _brand_lookalike(domain: str) -> str:
    if not domain or domain in SAFE_PLATFORM_DOMAINS:
        return ""
    sld = domain.split(".", 1)[0]
    if len(sld) < 5:
        return ""
    best: tuple[int, str, str] | None = None
    for bd in BRAND_DOMAINS:
        b_sld = bd.split(".", 1)[0]
        if len(b_sld) < 5:
            continue
        d = Levenshtein.distance(sld, b_sld)
        if best is None or d < best[0]:
            best = (d, b_sld, bd)
            if d == 0:
                break
    if not best:
        return ""
    dist, b_sld, match = best
    if dist == 0:
        return ""
    if dist <= 1:
        return match
    if dist == 2 and len(sld) >= 9:
        return match
    return ""


def _wildcard_match(host: str, san: str) -> bool:
    host = (host or "").lower()
    san = (san or "").lower()
    if not host or not san:
        return False
    if san.startswith("*."):
        base = san[2:]
        return host.endswith("." + base) and host.count(".") >= base.count(".") + 1
    return host == san


@lru_cache(maxsize=4096)
def _cached_domain_age(domain: str) -> int | None:
    return domain_age_days(domain, now=datetime.now(timezone.utc))


@lru_cache(maxsize=4096)
def _cached_ns(domain: str) -> tuple[str, ...]:
    return tuple(ns_records(domain))


@lru_cache(maxsize=4096)
def _cached_tls(host: str) -> dict | None:
    return tls_info(host)


@lru_cache(maxsize=4096)
def _cached_vt(url: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    return virustotal_url_report(url, api_key)


@lru_cache(maxsize=4096)
def _cached_urlhaus(url: str, key: str) -> dict | None:
    if not key:
        return None
    return urlhaus_url_info(url, key)


def _urlhaus_key() -> str:
    for k in ("URLHAUS_AUTH_KEY", "URLHAUS_API_KEY", "URLHAUS_KEY"):
        v = os.getenv(k, "").strip()
        if v:
            return v
    return ""


def expand_and_check(link: LinkFound, online: bool = False) -> CheckedURL:
    url = link.url
    flags: list[str] = []
    notes: list[str] = []

    dom = _domain_of(url)
    host = _host_of(url)

    p0 = urlparse(url)
    scheme0 = (p0.scheme or "").lower()

    path_low = (p0.path or "").lower() + " " + (p0.query or "").lower()
    is_unsub = any(tok in path_low for tok in UNSUB_TOKENS)
    if is_unsub:
        flags.append("unsub_link")

    if scheme0 == "http":
        if is_unsub:
            flags.append("not_https_unsub")
        else:
            flags.append("not_https")
    if p0.username or p0.password:
        flags.append("userinfo_in_url")
    if host and _looks_like_ip(host):
        flags.append("ip_in_host")

    if dom:
        if dom in SHORTENER_DOMAINS and dom not in SAFE_PLATFORM_DOMAINS:
            flags.append("shortener")
        if any(dom.endswith(t) for t in DANGER_TLDS):
            flags.append("suspicious_tld")

    flags.extend(_idn_flags(host))
    flags.extend(_path_token_flags(url))

    if dom and _visible_text_mismatch(link, dom):
        flags.append("link_text_mismatch")

    lookalike = _brand_lookalike(dom)
    if lookalike:
        flags.append("lookalike_domain")
        notes.append(f"Похож на {lookalike}")

    final_url, final_dom, final_host, red_count = url, dom, host, 0
    if online:
        r = safe_head_then_get(url, timeout=6)
        if r is None:
            flags.append("network_error")
        else:
            try:
                final_url = getattr(r, "url", url) or url
                red_count = len(getattr(r, "history", []) or [])
                final_dom = _domain_of(final_url)
                final_host = _host_of(final_url)
            except Exception:
                flags.append("network_error")

    if online and final_dom:
        age = _cached_domain_age(final_dom)
        if isinstance(age, int):
            notes.append(f"Возраст домена: {age}д")
            if age < 7:
                flags.append("domain_new_7d")
            elif age < 30:
                flags.append("domain_new_30d")
            elif age < 90:
                flags.append("domain_new_90d")
            elif age >= 300:
                flags.append("domain_old_300d")
                if age >= 1000:
                    flags.append("domain_old_1000d")

        ns = _cached_ns(final_dom)
        if not ns:
            flags.append("dns_no_ns")
        else:
            dynamic = any(
                any(
                    x in n
                    for x in (
                        "duckdns",
                        "no-ip",
                        "dyndns",
                        "ddns",
                        "hopto",
                        "servehttp",
                        "serveftp",
                        "myftp",
                        "myvnc",
                    )
                )
                for n in ns
            )
            if dynamic:
                flags.append("dns_dynamic_ns")
            notes.append(
                "NS: "
                + ", ".join(ns[:4])
                + ("" if len(ns) <= 4 else f" (+{len(ns)-4})")
            )

    scheme_final = (urlparse(final_url).scheme or "").lower()
    if online and scheme_final == "https" and final_host:
        info = _cached_tls(final_host)
        if info:
            age = cert_age_days(info, now=datetime.now(timezone.utc))
            if isinstance(age, int):
                notes.append(f"TLS cert: {age}д")
                if age < 7:
                    flags.append("tls_cert_very_fresh")
                elif age < 30:
                    flags.append("tls_cert_fresh")
            sans = info.get("sans") if isinstance(info, dict) else None
            if isinstance(sans, list) and sans:
                ok = any(_wildcard_match(final_host, s) for s in sans)
                if not ok:
                    rd = _registered_domain(final_host)
                    ok2 = any(_wildcard_match(rd, s) for s in sans)
                    if not ok2:
                        flags.append("tls_san_mismatch")
                notes.append(
                    "SAN: "
                    + ", ".join(sans[:6])
                    + ("" if len(sans) <= 6 else f" (+{len(sans)-6})")
                )

    if online and final_url:
        vt_key = os.getenv("VT_API_KEY", "").strip()
        if vt_key:
            rep = _cached_vt(final_url, vt_key)
            if isinstance(rep, dict):
                try:
                    stats = (
                        rep.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    mal = int(stats.get("malicious", 0) or 0)
                    susp = int(stats.get("suspicious", 0) or 0)
                    if mal > 0:
                        flags.append("intel_vt_malicious")
                        notes.append(f"VT malicious: {mal}")
                    elif susp > 0:
                        flags.append("intel_vt_suspicious")
                        notes.append(f"VT suspicious: {susp}")
                except Exception:
                    pass

        uh_key = _urlhaus_key()
        if uh_key:
            rep = _cached_urlhaus(final_url, uh_key)
            if isinstance(rep, dict):
                qs = rep.get("query_status")
                if qs == "ok":
                    flags.append("intel_urlhaus_listed")
                    url_status = rep.get("url_status")
                    threat = rep.get("threat")
                    bl = (
                        rep.get("blacklists", {})
                        if isinstance(rep.get("blacklists"), dict)
                        else {}
                    )
                    spamhaus = bl.get("spamhaus_dbl")
                    surbl = bl.get("surbl")
                    notes.append(
                        f"URLhaus: {str(url_status or '').strip()} {str(threat or '').strip()}".strip()
                    )
                    if spamhaus and spamhaus != "not listed":
                        notes.append(f"Spamhaus DBL: {spamhaus}")
                    if surbl and surbl != "not listed":
                        notes.append(f"SURBL: {surbl}")

    is_https = (urlparse(final_url).scheme or "").lower() == "https"
    return CheckedURL(url, final_url, final_dom, red_count, is_https, flags, notes)


def check_all_links(links: list[LinkFound], online: bool = False) -> list[CheckedURL]:
    out: list[CheckedURL] = []
    for l in links:
        u = (l.url or "").strip()
        if not u.lower().startswith(("http://", "https://")):
            continue
        out.append(expand_and_check(l, online))
    return out
