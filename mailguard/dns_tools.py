import dns.resolver

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 2.0
_RESOLVER.lifetime = 2.0

def mx_records(domain: str) -> list[str]:
    try:
        ans = _RESOLVER.resolve(domain, "MX")
        out: list[str] = []
        for r in ans:
            out.append(str(r.exchange).rstrip(".").lower())
        return out
    except Exception:
        return []

def ns_records(domain: str) -> list[str]:
    try:
        ans = _RESOLVER.resolve(domain, "NS")
        out: list[str] = []
        for r in ans:
            out.append(str(r.target).rstrip(".").lower())
        return out
    except Exception:
        return []
