import math
import re
from email.utils import parseaddr

import tldextract

from .my_types import ParsedEmail, CheckedURL
from .dns_tools import mx_records, ns_records
from .rdap_tools import domain_age_days
from .text_analyzer import analyze_text, ml_classify_text, TextAnalysis
from .domain_reputation import (
    domain_randomness_score,
    is_trusted_external,
    parse_dmarc_policy,
    detect_esp_from_headers,
    is_known_esp,
    TRUSTED_EXTERNAL_PLATFORMS,
)


_TLDX = tldextract.TLDExtract(suffix_list_urls=None)

_DYNAMIC_NS_TOKENS = (
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

_DANGER_FROM_TLDS = (
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".shop",
    ".icu",
    ".click",
    ".cfd",
    ".live",
    ".win",
    ".bid",
    ".gift",
    ".buzz",
    ".rest",
    ".surf",
    ".monster",
    ".sbs",
)

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.jp",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "aol.com",
    "mail.ru",
    "bk.ru",
    "list.ru",
    "inbox.ru",
    "yandex.ru",
    "yandex.com",
    "ya.ru",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "zoho.com",
    "gmx.com",
    "gmx.de",
    "rambler.ru",
    "tutanota.com",
    "tutamail.com",
}

_BRANDS = {
    "wildberries": {
        "keywords": [
            r"\bwildberries\b",
            r"\bwil[d]?berr(?:y|ies)\b",
            r"\bwilber(?:ri|rie|ries)\b",
            r"\bwb\b",
            r"\bвилдберриз\b",
            r"\bвайлдберриз\b",
            r"\bвилбери(?:з|с)?\b",
        ],
        "domains": {"wildberries.ru", "wb.ru", "wildberries.com"},
    },
    "ozon": {
        "keywords": [r"\bozon\b", r"\bозон\b"],
        "domains": {"ozon.ru", "ozon.com"},
    },
    "tbank": {
        "keywords": [
            r"\bт\s*[-–]?\s*банк\b",
            r"\bt\s*[-–]?\s*bank\b",
            r"\btbank\b",
            r"\bтинькофф\b",
            r"\btinkoff\b",
        ],
        "domains": {"tbank.ru", "tinkoff.ru", "t-bank.ru"},
    },
    "sber": {
        "keywords": [r"\bсбер\b", r"\bсбербанк\b", r"\bsber\b", r"\bsberbank\b"],
        "domains": {"sber.ru", "sberbank.ru", "sbbol.ru"},
    },
    "vtb": {
        "keywords": [r"\bвтб\b", r"\bvtb\b"],
        "domains": {"vtb.ru"},
    },
    "alfa": {
        "keywords": [r"\bальфа.?банк\b", r"\balfabank\b", r"\balfa\s*bank\b"],
        "domains": {"alfabank.ru"},
    },
    "avito": {
        "keywords": [r"\bавито\b", r"\bavito\b"],
        "domains": {"avito.ru"},
    },
    "gosuslugi": {
        "keywords": [r"\bгосуслуг\b", r"\bgosuslugi\b"],
        "domains": {"gosuslugi.ru", "esia.gosuslugi.ru"},
    },
}


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1 / (1 + z)
    z = math.exp(x)
    return z / (1 + z)


def _e(delta: float, msg: str) -> tuple[float, str]:
    return float(delta), msg


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


def _registered_domain_from_email(addr: str | None) -> str:
    if not addr:
        return ""
    _, em = parseaddr(addr)
    if "@" not in em:
        return ""
    host = em.split("@", 1)[1].strip().lower().rstrip(".")
    return _registered_domain(host)


def _display_name(addr: str | None) -> str:
    if not addr:
        return ""
    name, _ = parseaddr(addr)
    return (name or "").strip()


def _is_free_provider(dom: str) -> bool:
    d = (dom or "").lower().strip(".")
    if not d:
        return False
    if d in FREE_EMAIL_PROVIDERS:
        return True
    return any(d.endswith("." + p) for p in FREE_EMAIL_PROVIDERS)


def _find_brands(text: str) -> set[str]:
    out: set[str] = set()
    for b, meta in _BRANDS.items():
        for kw in meta["keywords"]:
            if re.search(kw, text, flags=re.IGNORECASE):
                out.add(b)
                break
    return out


def _aligned_domain(a: str, b: str) -> bool:
    a = (a or "").lower().strip(".")
    b = (b or "").lower().strip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    if a.endswith("." + b) or b.endswith("." + a):
        return True
    return False


def _sld(dom: str) -> str:
    try:
        ext = _TLDX(dom or "")
        return (ext.domain or "").lower()
    except Exception:
        return ""


def _domain_affinity(a: str, b: str) -> bool:
    if _aligned_domain(a, b):
        return True
    sa = _sld(a)
    sb = _sld(b)
    if sa and sb and sa == sb and len(sa) >= 4:
        return True
    return False


def _dns_dynamic(ns: list[str]) -> bool:
    return any(any(tok in (s or "").lower() for tok in _DYNAMIC_NS_TOKENS) for s in ns)


def _auth_status(auth_results: str, key: str) -> str:
    if not auth_results:
        return ""
    m = re.search(
        rf"\b{re.escape(key)}\s*=\s*([a-z]+)\b",
        auth_results,
        flags=re.IGNORECASE,
    )
    return m.group(1).lower() if m else ""


def _is_undisclosed_recipients(to_header: str) -> bool:
    """Определяет «undisclosed-recipients» — типичный признак массовой рассылки."""
    if not to_header:
        return True
    low = to_header.lower().strip()
    return bool(
        "undisclosed" in low
        or re.match(r"^undisclosed[\s\-]*recipients", low)
        or low in ("", ";", ":;")
    )


def _domains_from_checked(checked_links: list[CheckedURL]) -> dict[str, dict]:
    doms: dict[str, dict] = {}
    for c in checked_links:
        d = (c.final_domain or "").lower().strip(".")
        if not d:
            continue
        if d not in doms:
            doms[d] = {
                "flags": set(),
                "examples": [],
                "redirect_max": 0,
                "flag_samples": {},
                "notes": [],
            }
        doms[d]["flags"].update(set(c.flags or []))
        doms[d]["redirect_max"] = max(
            int(doms[d]["redirect_max"]), int(c.redirect_count or 0)
        )
        if c.final_url and c.final_url not in doms[d]["examples"]:
            doms[d]["examples"].append(c.final_url)
        for f in c.flags or []:
            if f not in doms[d]["flag_samples"]:
                doms[d]["flag_samples"][f] = c.final_url or c.original_url
        for n in c.notes or []:
            if n not in doms[d]["notes"]:
                doms[d]["notes"].append(n)
    for d in list(doms.keys()):
        doms[d]["flags"] = sorted(list(doms[d]["flags"]))
    return doms


def _build_context(
    email: ParsedEmail,
    checked_links: list[CheckedURL],
    use_ml: bool = False,
) -> dict:
    from_dom = _registered_domain_from_email(email.from_)
    name = _display_name(email.from_)
    seed = " ".join([name or "", email.subject or "", (email.text or "")[:3000]])

    brands_content = _find_brands(seed)
    brand_domains: set[str] = set()
    for b in brands_content:
        brand_domains.update(set(_BRANDS[b]["domains"]))

    brands_sender = _find_brands(" ".join([name or "", email.subject or ""]))
    sender_brand_domains: set[str] = set()
    for b in brands_sender:
        sender_brand_domains.update(set(_BRANDS[b]["domains"]))

    brand_mismatch = False
    if (brands_content or brands_sender) and from_dom:
        ok = any(
            _domain_affinity(from_dom, bd)
            for bd in (brand_domains | sender_brand_domains)
        )
        brand_mismatch = not ok

    auth_text = (email.auth_results or "").strip()
    spf = _auth_status(auth_text, "spf")
    dkim = _auth_status(auth_text, "dkim")
    dmarc = _auth_status(auth_text, "dmarc")
    auth_good = bool((spf == "pass" and dkim == "pass") or dmarc == "pass")

    dmarc_policy, has_dmarc = parse_dmarc_policy(auth_text)

    esp_found, esp_name = detect_esp_from_headers(
        email.headers if isinstance(email.headers, dict) else {}
    )

    to_raw = getattr(email, "to", "") or ""
    undisclosed = _is_undisclosed_recipients(to_raw)

    low_subj = (email.subject or "").lower()
    forwardish = bool(
        re.search(
            r"\bfw:\b|\bfwd:\b|original message|переслан",
            low_subj + " " + (email.text or "")[:500].lower(),
        )
    )

    text_analysis = analyze_text(
        email.subject or "", email.text or "", email.html or ""
    )

    ml_score, ml_label = None, None
    if use_ml:
        content_for_ml = f"{email.subject or ''} {(email.text or '')[:800]}"
        ml_score, ml_label = ml_classify_text(content_for_ml, use_ml=True)
        if ml_score is not None:
            text_analysis.ml_score = ml_score
            text_analysis.ml_label = ml_label

    from_randomness = domain_randomness_score(from_dom) if from_dom else 0.0

    display_brand_impersonation = False
    if name and from_dom:
        display_brands = _find_brands(name)
        if display_brands:
            ok_dn = any(
                _domain_affinity(from_dom, bd)
                for b in display_brands
                for bd in _BRANDS[b]["domains"]
            )
            if not ok_dn:
                display_brand_impersonation = True

    return {
        "from_dom": from_dom,
        "from_is_free": _is_free_provider(from_dom),
        "brand_domains": brand_domains,
        "brands_content": brands_content,
        "brands_sender": brands_sender,
        "brand_mismatch_sender": brand_mismatch,
        "display_brand_impersonation": display_brand_impersonation,
        "auth_good": auth_good,
        "dmarc_policy": dmarc_policy,
        "has_dmarc": has_dmarc,
        "esp_found": esp_found,
        "esp_name": esp_name,
        "undisclosed_recipients": undisclosed,
        "aligned_ratio": 0.0,
        "any_suspicious_url": False,
        "hard_suspicious_url": False,
        "has_prize": text_analysis.has_prize_lure,
        "has_money": text_analysis.has_monetary_lure,
        "has_creds": text_analysis.has_credential_request,
        "has_urgent_threat": text_analysis.has_urgency and text_analysis.has_threat,
        "is_forwarded": forwardish,
        "text_analysis": text_analysis,
        "from_randomness": from_randomness,
    }


def _header_evidence(
    email: ParsedEmail,
    online: bool,
    ctx: dict,
) -> list[tuple[float, str]]:
    ev: list[tuple[float, str]] = []

    from_dom = ctx.get("from_dom") or _registered_domain_from_email(email.from_)
    from_is_free = bool(ctx.get("from_is_free"))
    reply_dom = _registered_domain_from_email(email.reply_to)
    ret_dom = _registered_domain_from_email(email.return_path)

    if from_dom and reply_dom and from_dom != reply_dom:

        is_esp, _ = is_known_esp(reply_dom)
        w = 0.35 if is_esp else 0.95
        ev.append(_e(w, f"Reply-To домен отличается от From: {reply_dom} ≠ {from_dom}"))
    if from_dom and ret_dom and from_dom != ret_dom:
        is_esp, _ = is_known_esp(ret_dom)
        w = 0.20 if is_esp else 0.65
        ev.append(
            _e(w, f"Return-Path домен отличается от From: {ret_dom} ≠ {from_dom}")
        )

    auth_text = (email.auth_results or "").strip()
    spf = _auth_status(auth_text, "spf")
    dkim = _auth_status(auth_text, "dkim")
    dmarc = _auth_status(auth_text, "dmarc")

    if spf in ("fail", "permerror", "temperror"):
        ev.append(_e(1.15, f"SPF: {spf}"))
    elif spf == "softfail":
        ev.append(_e(0.70, f"SPF: {spf}"))
    elif spf in ("none", "neutral", "policy"):
        ev.append(_e(0.25, f"SPF: {spf}"))
    elif spf == "pass":
        ev.append(_e(-0.12 if not from_is_free else -0.04, "SPF pass"))

    if dkim in ("fail", "permerror", "temperror"):
        ev.append(_e(1.05, f"DKIM: {dkim}"))
    elif dkim in ("none", "neutral", "policy"):
        ev.append(_e(0.20, f"DKIM: {dkim}"))
    elif dkim == "pass":
        ev.append(_e(-0.12 if not from_is_free else -0.04, "DKIM pass"))

    if dmarc in ("fail", "permerror", "temperror"):
        ev.append(_e(1.25, f"DMARC: {dmarc}"))
    elif dmarc in ("none", "neutral", "policy"):
        ev.append(_e(0.16, f"DMARC: {dmarc}"))
    elif dmarc == "pass":
        ev.append(_e(-0.08 if not from_is_free else -0.02, "DMARC pass"))

    dmarc_policy = ctx.get("dmarc_policy")
    if dmarc == "pass" and dmarc_policy == "reject" and not from_is_free:
        ev.append(_e(-0.45, "DMARC policy: REJECT (сильная защита домена)"))
    elif dmarc == "pass" and dmarc_policy == "quarantine" and not from_is_free:
        ev.append(_e(-0.25, "DMARC policy: QUARANTINE"))
    elif dmarc == "pass" and dmarc_policy == "none" and not from_is_free:
        ev.append(_e(-0.05, "DMARC policy: NONE (слабая)"))

    auth_good = bool(ctx.get("auth_good"))
    if auth_good and not from_is_free:
        ev.append(_e(-0.06, "Аутентификация в целом выглядит корректно"))

    if bool(ctx.get("display_brand_impersonation")):
        brands = set(ctx.get("brands_sender") or set())
        bn = ", ".join(sorted(brands)) if brands else "бренд"
        w = 1.40 if from_is_free else 1.20

        if from_dom and any(from_dom.endswith(t) for t in _DANGER_FROM_TLDS):
            w += 0.30
        ev.append(
            _e(w, f"Display name содержит бренд ({bn}), но домен не связан: {from_dom}")
        )
    elif bool(ctx.get("brand_mismatch_sender")):
        brands = set(ctx.get("brands_content") or set()) | set(
            ctx.get("brands_sender") or set()
        )
        bn = ", ".join(sorted(brands))
        ev.append(
            _e(
                1.20 if from_is_free else 1.00,
                f"Упоминание бренда ({bn}), но домен отправителя не относится к бренду: {from_dom}",
            )
        )

    msgid_vals = (
        (email.headers.get("Message-ID") or [])
        if isinstance(email.headers, dict)
        else []
    )
    msgid = str(msgid_vals[0]) if msgid_vals else ""
    if not msgid.strip():
        ev.append(_e(0.22, "Отсутствует Message-ID"))
    else:
        m = re.search(r"@([^>\s]+)", msgid)
        if m and from_dom:
            mid_dom = _registered_domain(m.group(1))

            is_esp, _ = is_known_esp(mid_dom)
            if mid_dom and not _aligned_domain(from_dom, mid_dom) and not is_esp:
                ev.append(
                    _e(
                        0.20,
                        f"Message-ID домен не совпадает с From: {mid_dom} ≠ {from_dom}",
                    )
                )

    if from_dom and any(from_dom.endswith(t) for t in _DANGER_FROM_TLDS):
        ev.append(_e(0.70, f"Подозрительная зона домена отправителя: {from_dom}"))

    from_rnd = float(ctx.get("from_randomness") or 0.0)
    if from_rnd >= 0.55 and not from_is_free:
        ev.append(
            _e(
                0.50,
                f"Имя домена отправителя выглядит случайным (randomness={from_rnd:.2f}): {from_dom}",
            )
        )
    elif from_rnd >= 0.40 and not from_is_free:
        ev.append(
            _e(
                0.25,
                f"Имя домена отправителя малоосмысленно (randomness={from_rnd:.2f}): {from_dom}",
            )
        )

    if bool(ctx.get("undisclosed_recipients")):

        w = 0.35
        if bool(ctx.get("brand_mismatch_sender")) or bool(
            ctx.get("display_brand_impersonation")
        ):
            w = 0.65
        ev.append(
            _e(w, "To: undisclosed-recipients (скрытые получатели / массовая рассылка)")
        )

    if isinstance(email.headers, dict) and (
        "List-Unsubscribe" in email.headers or "List-Unsubscribe-Post" in email.headers
    ):
        ev.append(_e(-0.12, "Есть List-Unsubscribe (типично для легитимных рассылок)"))

    if bool(ctx.get("esp_found")):

        ev.append(_e(-0.05, f"Отправлено через ESP: {ctx.get('esp_name', '?')}"))

    spam_flag = (
        (email.headers.get("X-Spam-Flag") or [])
        if isinstance(email.headers, dict)
        else []
    )
    if spam_flag and any("yes" in str(v).lower() for v in spam_flag):
        ev.append(_e(1.10, "X-Spam-Flag: YES"))

    y_spam = (
        (email.headers.get("X-Yandex-Spam") or [])
        if isinstance(email.headers, dict)
        else []
    )
    if y_spam:
        try:
            v = float(str(y_spam[0]).strip())
            if v >= 5:
                ev.append(
                    _e(
                        1.55,
                        f"Провайдер дал высокую spam-оценку (X-Yandex-Spam: {v:g})",
                    )
                )
            elif v >= 4:
                ev.append(_e(1.10, f"Провайдер дал spam-оценку (X-Yandex-Spam: {v:g})"))
            elif v >= 3:
                ev.append(_e(0.80, f"Провайдер дал spam-оценку (X-Yandex-Spam: {v:g})"))
        except Exception:
            pass

    g_spam = (
        (email.headers.get("X-Gm-Spam") or [])
        if isinstance(email.headers, dict)
        else []
    )
    if g_spam and any(str(v).strip() == "1" for v in g_spam):
        ev.append(_e(1.20, "Gmail пометил как спам (X-Gm-Spam: 1)"))

    if bool(ctx.get("is_forwarded")):

        ev.append(_e(0.15, "Письмо переслано (Fw/Fwd)"))

    if online and from_dom and not from_is_free:
        try:
            age = domain_age_days(from_dom)
        except Exception:
            age = None
        if isinstance(age, int) and age > 0:
            if age < 30:
                ev.append(_e(0.80, f"Очень новый домен отправителя (<30д): {from_dom}"))
            elif age < 90:
                ev.append(_e(0.45, f"Новый домен отправителя (<90д): {from_dom}"))
            elif age >= 1000:
                ev.append(_e(-0.35, f"Старый домен отправителя: {from_dom}"))
            elif age >= 300:
                ev.append(_e(-0.25, f"Домен отправителя не новый (>10мес): {from_dom}"))

        try:
            mx = mx_records(from_dom)
        except Exception:
            mx = []
        if not mx:
            ev.append(_e(0.55, f"У домена отправителя нет MX-записей: {from_dom}"))

        try:
            ns = ns_records(from_dom)
        except Exception:
            ns = []
        if ns and _dns_dynamic(ns):
            ev.append(_e(0.25, f"NS похожи на динамический DNS: {from_dom}"))

    return ev


def _url_evidence(
    email: ParsedEmail,
    checked_links: list[CheckedURL],
    ctx: dict,
) -> list[tuple[float, str]]:
    ev: list[tuple[float, str]] = []
    from_dom = ctx.get("from_dom") or _registered_domain_from_email(email.from_)
    from_is_free = bool(ctx.get("from_is_free"))
    brand_domains: set[str] = set(ctx.get("brand_domains") or set())
    doms = _domains_from_checked(checked_links)
    ctx["link_domains_count"] = len(doms)
    if not doms:
        return ev

    brands = set(ctx.get("brands_content") or set()) | set(
        ctx.get("brands_sender") or set()
    )
    sender_brand_domains: set[str] = set()
    for b in brands:
        sender_brand_domains.update(set(_BRANDS[b]["domains"]))

    def is_aligned_or_trusted(d: str) -> bool:
        if from_dom and _domain_affinity(from_dom, d):
            return True
        for bd in brand_domains:
            if d == bd or d.endswith("." + bd):
                return True
        return False

    aligned = {d for d in doms.keys() if is_aligned_or_trusted(d)}
    trusted_ext = {d for d in doms.keys() if is_trusted_external(d)}

    effective_safe = aligned | trusted_ext
    aligned_ratio = len(effective_safe) / max(1, len(doms))
    ctx["aligned_ratio"] = aligned_ratio

    hard_susp_flags = {
        "shortener",
        "lookalike_domain",
        "ip_in_host",
        "userinfo_in_url",
        "suspicious_tld",
        "idn_in_host",
        "mixed_scripts",
        "intel_vt_malicious",
        "intel_urlhaus_listed",
        "intel_vt_suspicious",
    }

    hard_susp = False
    any_susp = False

    truly_unaligned = set(doms.keys()) - aligned - trusted_ext
    if (from_dom or brand_domains) and len(truly_unaligned) > 0 and not aligned:

        if truly_unaligned == set(doms.keys()):
            w = 1.55
            if from_is_free:
                w += 0.20
            if bool(ctx.get("brand_mismatch_sender")):
                w += 0.35
            ev.append(_e(w, "Ни одна ссылка не принадлежит домену/бренду отправителя"))
        else:

            w = 0.70
            if from_is_free:
                w += 0.15
            if bool(ctx.get("brand_mismatch_sender")):
                w += 0.20
            ev.append(_e(w, "Основные ссылки не связаны с доменом отправителя"))

    if (from_dom or brand_domains) and aligned and aligned_ratio >= 0.6:
        if not bool(ctx.get("brand_mismatch_sender")):
            ev.append(
                _e(-0.40, "Большинство ссылок ведут на домен, связанный с отправителем")
            )

    if len(doms) >= 4 and aligned_ratio < 0.5:
        ev.append(_e(0.40, f"Много разных доменов в ссылках: {len(doms)}"))

    http_external = 0
    for dom, info in doms.items():
        flags = set(info.get("flags") or [])
        ex = info.get("examples") or []
        sample0 = ex[0] if ex else dom
        is_aln = dom in aligned
        is_trust = dom in trusted_ext

        if "not_https" in flags:
            if is_aln or is_trust:
                w = 0.15
            else:
                w = 0.55
                http_external += 1
            ev.append(_e(w, f"Ссылка по HTTP: {sample0}"))

        rc = int(info.get("redirect_max") or 0)
        if rc >= 5:
            ev.append(
                _e(0.32 if not is_aln else 0.16, f"Много редиректов ({rc}): {sample0}")
            )
        elif rc >= 3:
            ev.append(
                _e(
                    0.18 if not is_aln else 0.10,
                    f"Цепочка редиректов ({rc}): {sample0}",
                )
            )

        if is_aln or is_trust:
            if "domain_old_1000d" in flags:
                ev.append(_e(-0.14, f"Старый домен ссылки: {dom}"))
            elif "domain_old_300d" in flags:
                ev.append(_e(-0.10, f"Домен ссылки не новый (>10мес): {dom}"))
        else:
            if "domain_new_7d" in flags:
                ev.append(_e(0.95, f"Очень новый домен ссылки (<7д): {dom}"))
            elif "domain_new_30d" in flags:
                ev.append(_e(0.70, f"Новый домен ссылки (<30д): {dom}"))
            elif "domain_new_90d" in flags:
                ev.append(_e(0.35, f"Домен ссылки довольно новый (<90д): {dom}"))

        for f in flags:
            if f in hard_susp_flags:
                any_susp = True
                msg = f"Сигнал по ссылке: {dom} ({f})"
                if f == "shortener":
                    msg = f"Сокращатель ссылок: {sample0}"
                elif f == "lookalike_domain":
                    msg = f"Похожий на бренд домен: {dom}"
                elif f == "ip_in_host":
                    msg = f"IP вместо домена в ссылке: {sample0}"
                elif f == "userinfo_in_url":
                    msg = f"Подозрительный формат userinfo: {sample0}"
                elif f == "suspicious_tld":
                    msg = f"Подозрительная зона домена ссылки: {dom}"
                elif f in {"idn_in_host", "mixed_scripts"}:
                    msg = f"Возможный гомограф/IDN: {dom}"
                elif f == "intel_vt_malicious":
                    msg = f"VirusTotal: вредоносная ссылка ({dom})"
                elif f == "intel_vt_suspicious":
                    msg = f"VirusTotal: подозрительно ({dom})"
                elif f == "intel_urlhaus_listed":
                    msg = f"URLhaus: ссылка в базе угроз ({dom})"

                w = 0.85
                if is_aln:
                    w = 0.30
                    if f in {
                        "lookalike_domain",
                        "ip_in_host",
                        "userinfo_in_url",
                        "suspicious_tld",
                        "idn_in_host",
                        "mixed_scripts",
                    }:
                        w = 0.45
                    if "domain_old_300d" in flags or "domain_old_1000d" in flags:
                        w *= 0.6
                elif is_trust:
                    w = 0.40
                else:
                    hard_susp = True
                ev.append(_e(w, msg))

            elif f == "path_phish_token":
                any_susp = True
                if is_aln or is_trust:
                    w = 0.08
                else:
                    w = 0.60
                    hard_susp = True
                ev.append(_e(w, f"Фишинговые слова в пути: {sample0}"))

            elif f == "network_error":
                any_susp = True
                ev.append(_e(0.10, f"Сетевой сбой при проверке: {dom}"))

            elif f == "unsub_link":
                ev.append(_e(-0.06, f"Ссылка отписки: {dom}"))

    if not aligned and http_external >= 1:
        ev.append(_e(1.05, "Внешние HTTP-ссылки при отсутствии связи с отправителем"))

    if from_is_free and not aligned and aligned_ratio < 0.3:
        non_trust = [d for d in doms.keys() if d not in trusted_ext]
        if len(non_trust) >= 1:
            w = 0.75
            if bool(ctx.get("has_money")):
                w += 0.35
            if bool(ctx.get("is_forwarded")):
                w += 0.20
            ev.append(_e(w, "Отправитель с публичного домена и все ссылки внешние"))

    if brands and sender_brand_domains:
        any_brand_link = any(
            d == bd or d.endswith("." + bd)
            for d in doms.keys()
            for bd in sender_brand_domains
        )
        if not any_brand_link and bool(ctx.get("brand_mismatch_sender")):
            bn = ", ".join(sorted(brands))
            ev.append(_e(0.85, f"Ссылки не ведут на официальный домен бренда ({bn})"))

    if not aligned and (
        bool(ctx.get("has_prize"))
        or bool(ctx.get("has_creds"))
        or bool(ctx.get("has_urgent_threat"))
    ):
        ev.append(_e(0.85, "Подозрительный текст + ссылки не связаны с отправителем"))

    if (
        from_is_free
        and not aligned
        and (bool(ctx.get("has_prize")) or bool(ctx.get("has_creds")))
    ):
        ev.append(
            _e(
                0.45,
                "Письмо с массового почтового домена + признаки социальной инженерии",
            )
        )

    if bool(ctx.get("is_forwarded")) and not aligned and (http_external or hard_susp):
        ev.append(_e(0.55, "Переслано с внешними/подозрительными ссылками"))

    ctx["any_suspicious_url"] = any_susp or (http_external > 0)
    ctx["hard_suspicious_url"] = hard_susp
    return ev


def _text_evidence(email: ParsedEmail, ctx: dict) -> list[tuple[float, str]]:
    ev: list[tuple[float, str]] = []

    auth_good = bool(ctx.get("auth_good"))
    aligned_ratio = float(ctx.get("aligned_ratio") or 0.0)
    hard_susp_url = bool(ctx.get("hard_suspicious_url"))
    brand_mismatch = bool(ctx.get("brand_mismatch_sender"))
    from_is_free = bool(ctx.get("from_is_free"))

    content = " ".join([email.subject or "", email.text or ""]).strip()
    low = content.lower()

    ta: TextAnalysis | None = ctx.get("text_analysis")

    if ta and ta.phishing_score >= 0.75:
        w = 1.20 if (brand_mismatch or hard_susp_url or aligned_ratio < 0.5) else 0.30
        ev.append(_e(w, f"NLP-анализ: высокий фишинг-скор ({ta.phishing_score:.2f})"))
    elif ta and ta.phishing_score >= 0.50:
        w = 0.60 if (brand_mismatch or hard_susp_url or aligned_ratio < 0.5) else 0.15
        ev.append(_e(w, f"NLP-анализ: средний фишинг-скор ({ta.phishing_score:.2f})"))
    elif ta and ta.phishing_score <= 0.15:
        ev.append(
            _e(-0.20, f"NLP-анализ: низкий фишинг-скор ({ta.phishing_score:.2f})")
        )

    if ta and ta.ml_score is not None:
        if ta.ml_score >= 0.75:
            ev.append(
                _e(
                    0.80,
                    f"Нейросеть: высокая P(фишинг)={ta.ml_score:.2f}, метка: {ta.ml_label}",
                )
            )
        elif ta.ml_score >= 0.50:
            ev.append(
                _e(
                    0.40,
                    f"Нейросеть: средняя P(фишинг)={ta.ml_score:.2f}, метка: {ta.ml_label}",
                )
            )
        elif ta.ml_score <= 0.20:
            ev.append(
                _e(
                    -0.25,
                    f"Нейросеть: низкая P(фишинг)={ta.ml_score:.2f}, метка: {ta.ml_label}",
                )
            )

    if ta and ta.is_contact_form_injection:
        ev.append(_e(1.30, "Обнаружена вероятная инъекция через контактную форму"))

    if ta and len(ta.language_mix) >= 3:
        ev.append(
            _e(0.80, f"Подозрительное смешение языков: {', '.join(ta.language_mix)}")
        )
    elif ta and "cjk" in ta.language_mix and "cyrillic" in ta.language_mix:
        ev.append(_e(0.65, "Смешение CJK + кириллица (типично для инъекций)"))

    if ta and ta.suspicious_money_amounts:
        mx = max(ta.suspicious_money_amounts)
        if mx >= 50_000:
            w = 0.90 if (brand_mismatch or hard_susp_url or from_is_free) else 0.30
            ev.append(
                _e(
                    w,
                    f"Подозрительно крупные суммы в тексте: {ta.suspicious_money_amounts[:3]}",
                )
            )
        elif mx >= 5000:
            w = (
                0.45
                if (brand_mismatch or hard_susp_url or aligned_ratio < 0.5)
                else 0.10
            )
            ev.append(
                _e(w, f"Денежные суммы в тексте: {ta.suspicious_money_amounts[:3]}")
            )

    if email.text and re.search(
        r"^\s*(from|subject)\s*:\s*.*https?://",
        email.text,
        flags=re.IGNORECASE | re.MULTILINE,
    ):
        ev.append(
            _e(
                0.75 if aligned_ratio == 0.0 else 0.18,
                "URL в строке, похожей на заголовок, внутри письма",
            )
        )

    if email.html and re.search(r"<\s*form\b", email.html, flags=re.IGNORECASE):
        ev.append(
            _e(
                0.95 if (hard_susp_url or brand_mismatch or not auth_good) else 0.20,
                "В HTML есть <form>",
            )
        )
    if email.html and re.search(r"<\s*script\b", email.html, flags=re.IGNORECASE):
        ev.append(
            _e(
                0.95 if (hard_susp_url or brand_mismatch or not auth_good) else 0.25,
                "В HTML есть <script>",
            )
        )
    if email.html and re.search(r"<\s*iframe\b", email.html, flags=re.IGNORECASE):
        ev.append(
            _e(
                0.70 if (hard_susp_url or brand_mismatch or not auth_good) else 0.18,
                "В HTML есть <iframe>",
            )
        )

    if (
        brand_mismatch
        and (ctx.get("brands_content") or ctx.get("brands_sender"))
        and aligned_ratio < 0.5
    ):
        ev.append(
            _e(
                0.55 if from_is_free else 0.45,
                "Упоминание бренда не подтверждается доменами ссылок",
            )
        )

    if ta and ta.has_prize_lure:
        ev.append(
            _e(
                (
                    0.80
                    if (brand_mismatch or hard_susp_url or aligned_ratio < 0.5)
                    else 0.12
                ),
                "Обещание выигрыша/приза",
            )
        )

    if ta and ta.has_urgency and ta.has_threat:
        ev.append(
            _e(
                (
                    0.80
                    if (hard_susp_url or not auth_good or aligned_ratio < 0.5)
                    else 0.18
                ),
                "Тональность: срочно + угрозы/санкции",
            )
        )

    if ta and ta.has_credential_request:
        ev.append(
            _e(
                (
                    0.85
                    if (hard_susp_url or brand_mismatch or aligned_ratio < 0.5)
                    else 0.10
                ),
                "Запрос чувствительных данных (пароль/код/вход)",
            )
        )

    if (
        ta
        and ta.has_call_to_action
        and (hard_susp_url or aligned_ratio < 0.5 or brand_mismatch)
    ):
        ev.append(_e(0.25, "Сильный призыв перейти по ссылке"))

    if auth_good and hard_susp_url and aligned_ratio == 0.0:
        ev.append(_e(0.25, "Аутентификация pass не компенсирует подозрительные ссылки"))

    return ev


def _attachment_evidence(email: ParsedEmail) -> list[tuple[float, str]]:
    ev: list[tuple[float, str]] = []
    exes = (
        ".exe",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".bat",
        ".cmd",
        ".scr",
        ".com",
        ".pif",
        ".lnk",
        ".cpl",
        ".msi",
        ".jar",
        ".ps1",
        ".psm1",
        ".wsf",
        ".wsc",
        ".hta",
    )
    macros = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm")
    risky_arch = (
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
        ".rar",
        ".7z",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".cab",
    )

    for a in email.attachments or []:
        fn = (a.filename or "").lower()
        if fn.endswith(exes):
            ev.append(_e(1.40, f"Опасное вложение: {a.filename}"))
        elif fn.endswith(macros):
            ev.append(_e(0.95, f"Вложение с макросами: {a.filename}"))
        elif fn.endswith(risky_arch):
            ev.append(_e(0.45, f"Архив/образ: {a.filename}"))
        if fn and re.search(
            r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx)\.(exe|js|vbs|cmd|bat|ps1|hta)$",
            fn,
        ):
            ev.append(_e(1.20, f"Двойное расширение: {a.filename}"))
        if a.content_type and "html" in (a.content_type or "").lower():
            ev.append(_e(0.55, f"HTML-вложение: {a.filename or 'attachment'}"))

        if fn.endswith((".zip", ".rar", ".7z")):
            if a.size < 500:
                ev.append(_e(0.30, f"Очень маленький архив ({a.size}Б): {a.filename}"))
    return ev


def overall_score(
    email: ParsedEmail,
    checked_links: list[CheckedURL],
    online: bool = False,
    use_ml: bool = False,
) -> tuple[float, str, list[str]]:
    """
    Вычисляет общий риск фишинга.

    Возвращает (risk, level, reasons).
    """
    base_logit = -2.8
    ctx = _build_context(email, checked_links, use_ml=use_ml)

    evidence: list[tuple[float, str]] = []
    evidence.extend(_header_evidence(email, online, ctx))
    evidence.extend(_url_evidence(email, checked_links, ctx))
    evidence.extend(_text_evidence(email, ctx))
    evidence.extend(_attachment_evidence(email))

    logit = base_logit + sum(d for d, _ in evidence)
    risk = float(_sigmoid(logit))

    if risk >= 0.85:
        level = "🔴 Критический риск"
    elif risk >= 0.65:
        level = "🟠 Высокий риск"
    elif risk >= 0.40:
        level = "🟡 Средний риск"
    else:
        level = "🟢 Низкий риск"

    shown: list[str] = []
    for d, s in sorted(evidence, key=lambda x: abs(x[0]), reverse=True):
        if abs(d) < 0.04:
            continue
        shown.append(f"[{d:+.2f}] {s}")

    if not shown:
        shown = ["Сильных фишинговых сигналов не найдено."]

    return risk, level, shown
