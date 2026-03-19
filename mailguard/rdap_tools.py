import json
from datetime import datetime, timezone
from functools import lru_cache

from .net import safe_request

@lru_cache(maxsize=1)
def _bootstrap() -> dict:
    url = "https://data.iana.org/rdap/dns.json"
    r = safe_request("GET", url, allow_redirects=True, timeout=6, stream=False)
    if r is None or r.status_code >= 400:
        return {}
    try:
        return r.json()
    except Exception:
        try:
            return json.loads(r.text)
        except Exception:
            return {}

def _bases_for_domain(domain: str) -> list[str]:
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return []
    tld = parts[-1]
    b = _bootstrap()
    services = b.get("services") if isinstance(b, dict) else None
    if not isinstance(services, list):
        return []
    for entry in services:
        try:
            tlds, bases = entry
            if tld in [x.lstrip(".").lower() for x in tlds]:
                return [str(u) for u in bases]
        except Exception:
            continue
    return []

def _parse_dt(s: str) -> datetime | None:
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None

def rdap_domain(domain: str) -> dict | None:
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d:
        return None
    tries: list[str] = []
    tries.append(f"https://www.rdap.net/domain/{d}")
    for base in _bases_for_domain(d):
        base2 = base.rstrip("/")
        tries.append(f"{base2}/domain/{d}")
    for u in tries:
        r = safe_request("GET", u, allow_redirects=True, timeout=6, stream=False, headers={"Accept": "application/rdap+json"})
        if r is None:
            continue
        if r.status_code >= 400:
            continue
        try:
            return r.json()
        except Exception:
            continue
    return None

def domain_created_at(domain: str) -> datetime | None:
    j = rdap_domain(domain)
    if not isinstance(j, dict):
        return None
    events = j.get("events")
    if not isinstance(events, list):
        return None
    best: datetime | None = None
    for ev in events:
        if not isinstance(ev, dict):
            continue
        act = str(ev.get("eventAction", "")).lower()
        if act not in ("registration", "registered", "created"):
            continue
        dt = ev.get("eventDate")
        if not isinstance(dt, str):
            continue
        parsed = _parse_dt(dt)
        if parsed is None:
            continue
        if best is None or parsed < best:
            best = parsed
    return best

def domain_age_days(domain: str, now: datetime | None = None) -> int | None:
    created = domain_created_at(domain)
    if created is None:
        return None
    n = now or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    delta = n - created
    return max(0, int(delta.total_seconds() // 86400))
