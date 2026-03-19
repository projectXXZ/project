import base64
import json

from .net import safe_request

def _b64_url_id(url: str) -> str:
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return b.rstrip("=")

def virustotal_url_report(url: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    uid = _b64_url_id(url)
    api = f"https://www.virustotal.com/api/v3/urls/{uid}"
    r = safe_request("GET", api, allow_redirects=True, timeout=10, stream=False, headers={"x-apikey": api_key})
    if r is None or r.status_code >= 400:
        return None
    try:
        return r.json()
    except Exception:
        try:
            return json.loads(r.text)
        except Exception:
            return None

def urlhaus_url_info(url: str, auth_key: str) -> dict | None:
    if not auth_key:
        return None
    api = "https://urlhaus-api.abuse.ch/v1/url/"
    r = safe_request("POST", api, allow_redirects=True, timeout=10, stream=False, headers={"Auth-Key": auth_key}, data={"url": url})
    if r is None or r.status_code >= 400:
        return None
    try:
        return r.json()
    except Exception:
        try:
            return json.loads(r.text)
        except Exception:
            return None
