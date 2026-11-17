"""Network part: HTTP headers and TLS certificate."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

USER_AGENT = "webgrade/1.0 (+https://github.com/)"


@dataclass
class Page:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    cookies: list[str] = field(default_factory=list)


def normalize(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url


def fetch(url: str, timeout: int = 15) -> Page:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as err:   # 4xx/5xx still have headers worth checking
        resp = err
    headers = {k: v for k, v in resp.headers.items()}
    cookies = resp.headers.get_all("Set-Cookie") or []
    return Page(url, resp.geturl(), resp.status if hasattr(resp, "status") else resp.code, headers, cookies)


def redirects_to_https(host: str, timeout: int = 10) -> bool | None:
    """Does http://host send the visitor to https:// ?"""
    try:
        page = fetch(f"http://{host}", timeout)
        return page.final_url.startswith("https://")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def get_certificate(host: str, port: int = 443, timeout: int = 10) -> tuple[dict | None, str | None, str]:
    """Return (certificate, tls_version, error). Certificate is None if invalid."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(), tls.version(), ""
    except ssl.SSLCertVerificationError as exc:
        return None, None, f"invalid certificate: {exc.verify_message}"
    except (OSError, ssl.SSLError) as exc:
        return None, None, str(exc)


def host_of(url: str) -> tuple[str, int]:
    p = urlparse(url)
    return p.hostname or "", p.port or (443 if p.scheme == "https" else 80)
