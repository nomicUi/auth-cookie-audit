from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

import requests

from .audit import audit_set_cookie_headers


def _extract_set_cookie_from_header_text(text: str) -> list[str]:
    vals = []
    for line in text.splitlines():
        if line.lower().startswith("set-cookie:"):
            vals.append(line.split(":", 1)[1].strip())
    return vals


def _fetch_url(url: str) -> list[str]:
    r = requests.get(url, timeout=20, allow_redirects=True, headers={"User-Agent": "auth-cookie-audit/0.1"})
    # requests folds multiple Set-Cookie headers into a list-like object
    raw = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw, "headers") else None
    if raw:
        return list(raw)
    # fallback
    return r.headers.get("Set-Cookie", "").split("\n") if r.headers.get("Set-Cookie") else []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="auth-cookie-audit", description="Audit Set-Cookie headers for common security footguns")
    ap.add_argument("input", help="URL, a file path containing headers, or '-' for stdin")
    args = ap.parse_args(argv)

    inp = args.input.strip()

    set_cookie_values: list[str] = []

    if inp == "-":
        text = sys.stdin.read()
        set_cookie_values = _extract_set_cookie_from_header_text(text)
    elif urlparse(inp).scheme in ("http", "https"):
        set_cookie_values = _fetch_url(inp)
    else:
        with open(inp, "r", encoding="utf-8", errors="replace") as f:
            set_cookie_values = _extract_set_cookie_from_header_text(f.read())

    if not set_cookie_values:
        print("No Set-Cookie headers found.")
        return 2

    findings = audit_set_cookie_headers(set_cookie_values)

    # Group by cookie name
    by_name: dict[str, list[str]] = {}
    for fd in findings:
        by_name.setdefault(fd.cookie_name, []).append(f"{fd.severity}: {fd.message}")

    exit_code = 0
    for name, msgs in by_name.items():
        print(f"\n{name}")
        for m in msgs:
            print(f"  - {m}")
        if any(m.startswith("WARN") for m in msgs):
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
