import socket
import ssl
import ipaddress
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 5

def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved or obj.is_unspecified:
            return False
        return True
    except Exception:
        return False

def resolve_ips(host: str, port: int | None = None) -> list[str]:
    out: list[str] = []
    try:
        port_q = port or 443
        infos = socket.getaddrinfo(host, port_q, type=socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in out:
                out.append(ip)
    except Exception:
        return []
    return out

def host_is_safe_public(host: str) -> bool:
    ips = resolve_ips(host)
    if not ips:
        return False
    return all(is_public_ip(ip) for ip in ips)

def safe_request(method: str, url: str, allow_redirects: bool = True, timeout: int = DEFAULT_TIMEOUT, headers: dict | None = None, stream: bool = True, **kwargs) -> requests.Response | None:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        if not p.hostname:
            return None
        if not host_is_safe_public(p.hostname):
            return None
        h = {"User-Agent": "mailguard/1.0"}
        if headers:
            h.update(headers)
        r = requests.request(method=method, url=url, headers=h, timeout=timeout, allow_redirects=allow_redirects, stream=stream, **kwargs)
        return r
    except Exception:
        return None

def safe_head_then_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> requests.Response | None:
    r = safe_request("HEAD", url, timeout=timeout, allow_redirects=True, stream=True)
    if r is None:
        return None
    if r.status_code in (405, 501) or r.status_code >= 400:
        r2 = safe_request("GET", url, timeout=timeout, allow_redirects=True, stream=True, headers={"Range": "bytes=0-2048"})
        return r2
    return r

def fetch_tls_cert(host: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> dict | None:
    if not host_is_safe_public(host):
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None
