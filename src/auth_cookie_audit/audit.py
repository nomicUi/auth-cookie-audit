from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CookieFinding:
    cookie_name: str
    severity: str  # OK|WARN
    message: str


def _split_set_cookie_header(header_value: str) -> list[str]:
    # A single Set-Cookie header value is one cookie; servers may send multiple Set-Cookie headers.
    # We keep this simple and do not attempt to parse quoted commas; most cookies don't need it.
    return [p.strip() for p in header_value.split(";") if p.strip()]


def audit_set_cookie(header_value: str) -> list[CookieFinding]:
    parts = _split_set_cookie_header(header_value)
    if not parts:
        return []

    name_value = parts[0]
    cookie_name = name_value.split("=", 1)[0].strip() if "=" in name_value else name_value.strip()

    attrs = {p.lower(): p for p in parts[1:]}
    flags = set(a.split("=", 1)[0].strip().lower() for a in parts[1:])

    findings: list[CookieFinding] = []

    # HttpOnly
    if "httponly" not in flags:
        findings.append(CookieFinding(cookie_name, "WARN", "Missing HttpOnly"))

    # Secure
    if "secure" not in flags:
        findings.append(CookieFinding(cookie_name, "WARN", "Missing Secure"))

    # SameSite
    samesite = None
    for k in ("samesite",):
        if k in attrs:
            # original case-preserving
            raw = attrs[k]
            if "=" in raw:
                samesite = raw.split("=", 1)[1].strip()
            break

    if samesite is None:
        findings.append(CookieFinding(cookie_name, "WARN", "Missing SameSite"))
    else:
        ss = samesite.lower()
        if ss == "none" and "secure" not in flags:
            findings.append(CookieFinding(cookie_name, "WARN", "SameSite=None without Secure (will be rejected by modern browsers)"))

    # Domain
    for p in parts[1:]:
        if p.lower().startswith("domain="):
            dom = p.split("=", 1)[1].strip().lower().lstrip(".")
            # heuristic: warn if domain looks like a parent domain (contains only one dot would be rare; but keep simple)
            findings.append(CookieFinding(cookie_name, "WARN", f"Domain is set ({dom}). Ensure it’s not overly broad."))
            break

    # Path
    for p in parts[1:]:
        if p.lower().startswith("path="):
            path = p.split("=", 1)[1].strip()
            if path == "/":
                findings.append(CookieFinding(cookie_name, "WARN", "Path=/ (broad). Consider narrowing if possible."))
            break

    if not findings:
        findings.append(CookieFinding(cookie_name, "OK", "Cookie flags look sane"))

    return findings


def audit_set_cookie_headers(values: Iterable[str]) -> list[CookieFinding]:
    out: list[CookieFinding] = []
    for v in values:
        out.extend(audit_set_cookie(v))
    return out
