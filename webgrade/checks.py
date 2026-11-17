"""Pure analysis functions (no network) - easy to test."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie


@dataclass
class Result:
    name: str
    ok: bool
    penalty: int          # points removed from 100 when not ok
    detail: str
    advice: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def check_headers(headers: dict[str, str], is_https: bool) -> list[Result]:
    h = {k.lower(): v for k, v in headers.items()}
    out = []

    hsts = h.get("strict-transport-security", "")
    if is_https:
        m = re.search(r"max-age=(\d+)", hsts)
        age = int(m.group(1)) if m else 0
        out.append(Result("Strict-Transport-Security", age >= 15552000, 15,
                          hsts or "missing",
                          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))

    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(Result("Content-Security-Policy", False, 20, "missing",
                          "Define a CSP, e.g. default-src 'self' (start with Content-Security-Policy-Report-Only)"))
    else:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", " * ", "data:") if w in f" {csp} "]
        out.append(Result("Content-Security-Policy", not weak, 5,
                          "present" + (f" but weak: {', '.join(weak)}" if weak else ""),
                          "Avoid 'unsafe-inline' and 'unsafe-eval'" if weak else ""))

    xfo = h.get("x-frame-options", "").upper()
    frame_ancestors = "frame-ancestors" in csp
    out.append(Result("Clickjacking protection", xfo in ("DENY", "SAMEORIGIN") or frame_ancestors, 10,
                      f"X-Frame-Options: {xfo}" if xfo else ("CSP frame-ancestors" if frame_ancestors else "missing"),
                      "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')"))

    xcto = h.get("x-content-type-options", "").lower()
    out.append(Result("X-Content-Type-Options", xcto == "nosniff", 5, xcto or "missing",
                      "Add: X-Content-Type-Options: nosniff"))

    rp = h.get("referrer-policy", "").lower()
    out.append(Result("Referrer-Policy", bool(rp) and rp != "unsafe-url", 5, rp or "missing",
                      "Add: Referrer-Policy: strict-origin-when-cross-origin"))

    pp = h.get("permissions-policy", "")
    out.append(Result("Permissions-Policy", bool(pp), 5, "present" if pp else "missing",
                      "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"))

    # information leaks
    leaks = []
    server = h.get("server", "")
    if re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    for header in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if header in h:
            leaks.append(f"{header}: {h[header]}")
    out.append(Result("No version disclosure", not leaks, 5, "; ".join(leaks) or "nothing leaked",
                      "Hide versions (nginx: server_tokens off; PHP: expose_php = Off)"))
    return out


def check_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Result]:
    out = []
    for raw in set_cookie_headers:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        lower = raw.lower()
        for name in jar:
            problems = []
            if is_https and "secure" not in lower:
                problems.append("no Secure")
            if "httponly" not in lower:
                problems.append("no HttpOnly")
            if "samesite" not in lower:
                problems.append("no SameSite")
            out.append(Result(f"Cookie '{name}'", not problems, 5, ", ".join(problems) or "Secure, HttpOnly, SameSite",
                              "Set the cookie with: Secure; HttpOnly; SameSite=Lax"))
    return out


def check_certificate(cert: dict | None, tls_version: str | None, now: datetime | None = None) -> list[Result]:
    out = []
    if cert is None:
        return [Result("TLS certificate", False, 40, "could not get a valid certificate",
                       "Install a valid certificate (Let's Encrypt is free)")]
    now = now or datetime.now(timezone.utc)
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expires - now).days
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
    out.append(Result("Certificate expiry", days > 14, 20 if days < 0 else 10,
                      f"expires {expires:%Y-%m-%d} ({days} days), issuer {issuer}",
                      "Renew the certificate (certbot renew)"))
    if tls_version:
        out.append(Result("TLS version", tls_version in ("TLSv1.2", "TLSv1.3"), 20, tls_version,
                          "Disable TLS 1.0 / 1.1"))
    return out


def grade(results: list[Result]) -> tuple[int, str]:
    score = max(0, 100 - sum(r.penalty for r in results if not r.ok))
    for limit, letter in ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E")):
        if score >= limit:
            return score, letter
    return score, "F"
