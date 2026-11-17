"""webgrade command line."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error

from . import __version__
from .checks import Result, check_certificate, check_cookies, check_headers, grade
from .fetch import fetch, get_certificate, host_of, normalize, redirects_to_https

GRADE_COLOR = {"A": "\033[92m", "B": "\033[92m", "C": "\033[93m", "D": "\033[93m", "E": "\033[91m", "F": "\033[91m"}


def audit(url: str) -> dict:
    url = normalize(url)
    page = fetch(url)
    is_https = page.final_url.startswith("https://")
    host, port = host_of(page.final_url)

    results: list[Result] = []
    if is_https:
        cert, version, error = get_certificate(host, port)
        results += check_certificate(cert, version)
        if error:
            results[0].detail = error
        if url.startswith("https://"):
            redirect = redirects_to_https(host)
            if redirect is not None:
                results.append(Result("HTTP redirects to HTTPS", redirect, 10,
                                      "yes" if redirect else "http:// stays unencrypted",
                                      "Redirect all http:// traffic to https:// (301)"))
    else:
        results.append(Result("HTTPS", False, 40, "site served over plain HTTP",
                              "Enable HTTPS (Let's Encrypt is free)"))
    results += check_headers(page.headers, is_https)
    results += check_cookies(page.cookies, is_https)
    score, letter = grade(results)
    return {"url": url, "final_url": page.final_url, "status": page.status,
            "score": score, "grade": letter, "results": results}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="webgrade", description="Grade the security configuration of a website (A to F).")
    p.add_argument("urls", nargs="+", help="site(s) to check, e.g. example.com")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    reports, code = [], 0
    for url in args.urls:
        try:
            rep = audit(url)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"error: {url}: {getattr(exc, 'reason', exc)}", file=sys.stderr)
            code = 2
            continue
        reports.append(rep)
        if args.json:
            continue
        print(f"\n{rep['final_url']}  (HTTP {rep['status']})")
        for r in rep["results"]:
            mark = "\033[92m✔\033[0m" if (r.ok and color) else ("✔" if r.ok else ("\033[91m✘\033[0m" if color else "✘"))
            print(f"  {mark} {r.name:<28} {r.detail}")
            if not r.ok and r.advice:
                print(f"      -> {r.advice}")
        c, reset = (GRADE_COLOR[rep["grade"]], "\033[0m") if color else ("", "")
        print(f"\n  Score {rep['score']}/100   Grade {c}{rep['grade']}{reset}")

    if args.json:
        for rep in reports:
            rep["results"] = [r.to_dict() for r in rep["results"]]
        print(json.dumps(reports if len(reports) > 1 else (reports[0] if reports else {}), indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
