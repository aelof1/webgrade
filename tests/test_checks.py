from datetime import datetime, timezone

from webgrade.checks import check_certificate, check_cookies, check_headers, grade

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Server": "nginx",
}

BAD_HEADERS = {"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.24"}


def by_name(results):
    return {r.name: r for r in results}


def test_good_headers_get_a():
    results = check_headers(GOOD_HEADERS, is_https=True)
    assert all(r.ok for r in results), [r for r in results if not r.ok]
    assert grade(results) == (100, "A")


def test_bad_headers():
    r = by_name(check_headers(BAD_HEADERS, is_https=True))
    assert not r["Strict-Transport-Security"].ok
    assert not r["Content-Security-Policy"].ok
    assert not r["No version disclosure"].ok
    assert "PHP/7.2.24" in r["No version disclosure"].detail
    score, letter = grade(list(r.values()))
    assert letter in "DEF"


def test_weak_csp():
    r = by_name(check_headers({"Content-Security-Policy": "default-src * 'unsafe-inline'"}, True))
    assert not r["Content-Security-Policy"].ok and "unsafe-inline" in r["Content-Security-Policy"].detail


def test_cookies():
    results = check_cookies(["session=abc; Path=/", "pref=1; Secure; HttpOnly; SameSite=Lax"], is_https=True)
    r = by_name(results)
    assert not r["Cookie 'session'"].ok and "no HttpOnly" in r["Cookie 'session'"].detail
    assert r["Cookie 'pref'"].ok


def test_certificate_expiry():
    cert = {"notAfter": "Jan 10 12:00:00 2027 GMT", "issuer": ((("organizationName", "Let's Encrypt"),),)}
    now = datetime(2026, 11, 17, tzinfo=timezone.utc)
    r = by_name(check_certificate(cert, "TLSv1.3", now))
    assert r["Certificate expiry"].ok and "Let's Encrypt" in r["Certificate expiry"].detail
    soon = datetime(2027, 1, 5, tzinfo=timezone.utc)
    assert not by_name(check_certificate(cert, "TLSv1.3", soon))["Certificate expiry"].ok
    assert not by_name(check_certificate(cert, "TLSv1", now))["TLS version"].ok


def test_no_certificate():
    assert grade(check_certificate(None, None))[0] == 60
