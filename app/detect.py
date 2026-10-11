"""Decide what the user typed (domain / IP / URL / e-mail / hash / username) and validate it."""
import ipaddress
import re
from urllib.parse import urlparse

TYPES = ("domain", "ip", "url", "email", "hash", "username")
LABELS = {"domain": "Domain", "ip": "IP address", "url": "URL", "email": "E-mail address",
          "hash": "File hash", "username": "Username"}
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9\-\.]{1,253})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,62}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,38}$")
SECRET_HINTS = ("api_key", "apikey", "api-key", "password=", "passwd=", "token=", "secret=")
LOCAL_TLDS = {"local", "localhost", "internal", "lan", "corp", "home", "intranet", "test", "invalid"}


def _domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Domain contains invalid characters.")
    if not DOMAIN_RE.match(v):
        raise ValueError("That does not look like a valid domain (example: example.com).")
    if v.rsplit(".", 1)[-1] in LOCAL_TLDS:
        raise ValueError("Local or reserved domain names cannot be looked up.")
    return v


def _ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        raise ValueError("That is not a valid IPv4/IPv6 address.")
    if not ip.is_global:
        raise ValueError("Private, loopback and reserved IP addresses are not looked up (they are not public).")
    return str(ip)


def _url(value: str) -> str:
    p = urlparse(value.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("URL must start with http:// or https:// and include a host.")
    if p.username or p.password:
        raise ValueError("URLs containing a username/password are rejected.")
    host = p.hostname
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    _ip(host) if is_ip else _domain(host)
    return p._replace(fragment="").geturl()


def _email(value: str) -> str:
    v = value.strip()
    m = EMAIL_RE.match(v)
    if not m:
        raise ValueError("That does not look like a valid e-mail address.")
    _domain(m.group(1))
    return v.lower()


def _hash(value: str) -> str:
    v = value.strip()
    if not HASH_RE.match(v):
        raise ValueError("A file hash must be MD5 (32), SHA-1 (40) or SHA-256 (64) hex characters.")
    return v.lower()


def _username(value: str) -> str:
    v = value.strip().lstrip("@")
    if not USER_RE.match(v):
        raise ValueError("Usernames: 2-39 characters, letters/digits and . _ - only.")
    return v


VALIDATORS = {"domain": _domain, "ip": _ip, "url": _url, "email": _email, "hash": _hash, "username": _username}


def guess(raw: str) -> str:
    v = raw.strip()
    if "://" in v:
        return "url"
    if "@" in v and not v.startswith("@"):
        return "email"
    if HASH_RE.match(v):
        return "hash"
    try:
        ipaddress.ip_address(v.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if "." in v and re.match(r"^[^\s/@]+\.[A-Za-z][A-Za-z0-9\-]{1,62}\.?$", v):
        return "domain"
    return "username"


def normalize(raw: str, forced: str | None = None) -> tuple[str, str]:
    """Return (target_type, cleaned_value) or raise ValueError with a human message."""
    if raw is None or not raw.strip():
        raise ValueError("Enter something to investigate.")
    low = raw.lower()
    if any(h in low for h in SECRET_HINTS):
        raise ValueError("Input looks like it contains a credential. Remove it and try again.")
    if len(raw) > 2048 or any(ord(ch) < 32 for ch in raw):
        raise ValueError("Input is too long or contains control characters.")
    ttype = forced if forced and forced != "auto" else guess(raw)
    if ttype not in VALIDATORS:
        raise ValueError(f"Unknown target type '{ttype}'.")
    return ttype, VALIDATORS[ttype](raw)
