from datetime import datetime, timezone

from .net import fetch_tls_cert

def _parse_asn1_time(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        try:
            return datetime.strptime(s, "%b  %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None

def tls_info(host: str) -> dict | None:
    cert = fetch_tls_cert(host)
    if not cert:
        return None
    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    nb_dt = _parse_asn1_time(nb) if isinstance(nb, str) else None
    na_dt = _parse_asn1_time(na) if isinstance(na, str) else None
    sans: list[str] = []
    san = cert.get("subjectAltName")
    if isinstance(san, list):
        for typ, val in san:
            if typ == "DNS" and isinstance(val, str):
                sans.append(val.lower())
    return {
        "not_before": nb_dt,
        "not_after": na_dt,
        "sans": sorted(set(sans)),
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
    }

def cert_age_days(info: dict, now: datetime | None = None) -> int | None:
    nb = info.get("not_before")
    if not isinstance(nb, datetime):
        return None
    n = now or datetime.now(timezone.utc)
    delta = n - nb
    return max(0, int(delta.total_seconds() // 86400))
