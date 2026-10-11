"""Provider adapters. Every function takes (target_type, target) and returns a list of findings.

Findings are dicts: source, title, detail, severity, provenance.
provenance = "live" (came from a real external source just now), "system" (this app's own note)
or "error" (a lookup failed). There is NO simulated data anywhere in this project.
"""
import base64
import hashlib
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import dns.exception
import dns.resolver
import dns.reversename
import httpx

UA = "Tracepoint-OSINT-student-project/2.0"


class ProviderError(Exception):
    pass


def key(name: str) -> str:
    return os.getenv(name, "").strip()


def F(source, title, detail="", severity="info", provenance="live"):
    return {"source": source, "title": title, "detail": detail, "severity": severity, "provenance": provenance}


def http_get(url, headers=None, params=None, timeout=15):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    return httpx.get(url, headers=h, params=params, timeout=timeout, follow_redirects=True)


def http_post(url, headers=None, json=None, timeout=40):
    h = {"User-Agent": UA}
    h.update(headers or {})
    return httpx.post(url, headers=h, json=json, timeout=timeout)


def check(resp, name, ok=(200,)):
    if resp.status_code in ok:
        return
    if resp.status_code in (401, 403):
        raise ProviderError(f"{name}: access denied (HTTP {resp.status_code}). The key may be invalid, or your plan does not allow this lookup.")
    if resp.status_code == 429:
        raise ProviderError(f"{name}: rate limit or quota reached (HTTP 429). Try again later.")
    raise ProviderError(f"{name}: unexpected response (HTTP {resp.status_code}).")


def jget(resp, name):
    try:
        return resp.json()
    except ValueError:
        raise ProviderError(f"{name}: response was not valid JSON.")


def host_of(ttype, target):
    if ttype == "email":
        return target.split("@", 1)[1]
    if ttype == "url":
        return urlparse(target).hostname
    return target


def parse_dt(s):
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime, r.timeout = 6, 3
    return r


# ---------------------------------------------------------------- free / no-key sources
def dns_lookup(ttype, target):
    host = host_of(ttype, target)
    res, recs = _resolver(), {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            recs[rt] = [a.to_text() for a in res.resolve(host, rt)]
        except dns.resolver.NXDOMAIN:
            return [F("DNS", "Domain does not exist in DNS", f"{host} returned NXDOMAIN (no such domain).", "low")]
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            recs[rt] = []
        except dns.exception.Timeout:
            raise ProviderError("DNS: resolver timed out.")
        except dns.exception.DNSException as e:
            raise ProviderError(f"DNS: {type(e).__name__}")
    out = [F("DNS", f"{rt} records", "\n".join(v[:15])) for rt, v in recs.items() if v]
    if not any(recs.values()):
        return [F("DNS", "No DNS records found", f"{host} exists but has no A/AAAA/MX/NS/TXT records.", "low")]
    if recs["MX"]:
        if "v=spf1" not in " ".join(recs["TXT"]).lower():
            out.append(F("DNS", "No SPF record", "Domain receives mail but publishes no SPF policy (spoofing hygiene).", "low"))
        try:
            dm = [a.to_text() for a in res.resolve("_dmarc." + host, "TXT")]
            if not any("v=dmarc1" in x.lower() for x in dm):
                raise dns.resolver.NoAnswer
        except dns.exception.DNSException:
            out.append(F("DNS", "No DMARC record", "No _dmarc TXT policy found (spoofing hygiene).", "low"))
    return out


def _vcard_name(ent):
    for item in (ent.get("vcardArray") or [None, []])[1] or []:
        if item and item[0] == "fn":
            return item[3]
    return None


def rdap_domain(ttype, target):
    host = host_of(ttype, target)
    r = http_get(f"https://rdap.org/domain/{host}", timeout=20)
    if r.status_code == 404:
        return [F("RDAP", "No registration record", f"No RDAP record for {host} (subdomains and some TLDs are not registered separately).")]
    check(r, "RDAP")
    j = jget(r, "RDAP")
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar = next((_vcard_name(e) for e in j.get("entities", []) if "registrar" in e.get("roles", [])), None)
    ns = sorted({n.get("ldhName", "").lower() for n in j.get("nameservers", []) if n.get("ldhName")})
    lines = [f"Registrar: {registrar or 'not published'}",
             f"Registered: {ev.get('registration', 'unknown')}",
             f"Last changed: {ev.get('last changed', 'unknown')}",
             f"Expires: {ev.get('expiration', 'unknown')}",
             f"Status: {', '.join(j.get('status', [])) or 'unknown'}"]
    if ns:
        lines.append("Nameservers: " + ", ".join(ns[:8]))
    out = [F("RDAP", "Domain registration (WHOIS successor)", "\n".join(lines))]
    now = datetime.now(timezone.utc)
    reg, exp = parse_dt(ev.get("registration")), parse_dt(ev.get("expiration"))
    if reg:
        age = (now - reg).days
        if age < 30:
            out.append(F("RDAP", "Recently registered domain", f"Registered {age} day(s) ago. New domains are common in phishing.", "medium"))
        elif age < 90:
            out.append(F("RDAP", "Young domain", f"Registered {age} days ago.", "low"))
    if exp and exp < now:
        out.append(F("RDAP", "Registration appears expired", f"Expiry date {exp.date()} is in the past.", "medium"))
    return out


def rdap_ip(ttype, target):
    r = http_get(f"https://rdap.org/ip/{target}", timeout=20)
    if r.status_code == 404:
        return [F("RDAP", "No network record", "No RDAP allocation record for this address.")]
    check(r, "RDAP")
    j = jget(r, "RDAP")
    owner = next((_vcard_name(e) for e in j.get("entities", []) if _vcard_name(e)), None)
    d = [f"Network name: {j.get('name', 'unknown')}", f"Range: {j.get('startAddress', '?')} - {j.get('endAddress', '?')}",
         f"Country: {j.get('country', 'unknown')}", f"Type: {j.get('type', 'unknown')}", f"Registered to: {owner or 'not published'}"]
    return [F("RDAP", "Network allocation", "\n".join(d))]


def crtsh(ttype, target):
    r = http_get("https://crt.sh/", params={"q": "%." + target, "output": "json"}, timeout=30)
    check(r, "crt.sh")
    names = set()
    for row in jget(r, "crt.sh"):
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == target or n.endswith("." + target):
                names.add(n)
    if not names:
        return [F("Certificate Transparency", "No certificates found", "crt.sh has no public certificates for this domain.")]
    names = sorted(names)
    more = f"\n... and {len(names) - 40} more" if len(names) > 40 else ""
    return [F("Certificate Transparency", f"{len(names)} hostnames seen in public certificates", "\n".join(names[:40]) + more)]


RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
               5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}


def internetdb(ttype, target):
    r = http_get(f"https://internetdb.shodan.io/{target}", timeout=15)
    if r.status_code == 404:
        return [F("Shodan InternetDB", "No data for this IP", "Shodan has not observed open services on this address.")]
    check(r, "Shodan InternetDB")
    j = jget(r, "Shodan InternetDB")
    ports, vulns, tags = j.get("ports", []), j.get("vulns", []), j.get("tags", [])
    out = []
    if ports:
        out.append(F("Shodan InternetDB", f"{len(ports)} open ports observed", ", ".join(str(p) for p in sorted(ports)) +
                     ("\nHostnames: " + ", ".join(j["hostnames"][:10]) if j.get("hostnames") else "")))
        risky = [f"{p} ({RISKY_PORTS[p]})" for p in sorted(ports) if p in RISKY_PORTS]
        if risky:
            out.append(F("Shodan InternetDB", "Sensitive services exposed", ", ".join(risky), "medium"))
    if vulns:
        out.append(F("Shodan InternetDB", f"{len(vulns)} candidate CVEs", ", ".join(vulns[:20]) +
                     "\nBased on banner/version matching, so false positives are possible.", "high"))
    bad = [t for t in tags if t in ("malware", "compromised", "scanner", "tor", "self-signed")]
    if bad:
        out.append(F("Shodan InternetDB", "Tags: " + ", ".join(bad), "Tags assigned by Shodan.", "medium" if set(bad) & {"malware", "compromised"} else "low"))
    return out or [F("Shodan InternetDB", "Record exists, no open services listed", "")]


def geoip(ttype, target):
    r = http_get(f"https://ipwho.is/{target}", timeout=15)
    check(r, "ipwho.is")
    j = jget(r, "ipwho.is")
    if not j.get("success", False):
        return [F("GeoIP", "No geolocation data", str(j.get("message", "lookup unsuccessful")))]
    c = j.get("connection", {})
    d = [f"Location: {j.get('city', '?')}, {j.get('region', '?')}, {j.get('country', '?')}",
         f"ASN: AS{c.get('asn', '?')}  Organisation: {c.get('org', '?')}", f"ISP: {c.get('isp', '?')}"]
    return [F("GeoIP", "Geolocation and network owner", "\n".join(d) + "\nGeolocation is approximate.")]


def reverse_dns(ttype, target):
    try:
        ans = _resolver().resolve(dns.reversename.from_address(target), "PTR")
        return [F("DNS", "Reverse DNS (PTR)", "\n".join(a.to_text() for a in ans))]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [F("DNS", "No reverse DNS record", "")]
    except dns.exception.Timeout:
        raise ProviderError("DNS: reverse lookup timed out.")


def urlscan(ttype, target):
    q = f"ip:{target}" if ttype == "ip" else f"domain:{host_of(ttype, target)}"
    hdr = {"API-Key": key("URLSCAN_API_KEY")} if key("URLSCAN_API_KEY") else {}
    r = http_get("https://urlscan.io/api/v1/search/", headers=hdr, params={"q": q, "size": 10}, timeout=20)
    check(r, "urlscan.io")
    res = jget(r, "urlscan.io").get("results", [])
    if not res:
        return [F("urlscan.io", "No existing scans found", "Searches existing public scans only; this app never submits scans.")]
    lines = [f"{x.get('task', {}).get('time', '?')[:10]}  {x.get('page', {}).get('url', '?')}\n    https://urlscan.io/result/{x.get('_id')}/" for x in res[:8]]
    return [F("urlscan.io", f"{len(res)}+ public scans exist", "\n".join(lines))]


def hashlookup(ttype, target):
    kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(target)]
    r = http_get(f"https://hashlookup.circl.lu/lookup/{kind}/{target}", timeout=15)
    if r.status_code == 404:
        return [F("CIRCL hashlookup", "Not in known-file database", "The hash is not in CIRCL's known-FILE dataset. This does NOT mean it is malicious or safe; check VirusTotal.")]
    check(r, "CIRCL hashlookup")
    j = jget(r, "CIRCL hashlookup")
    d = [f"File name: {j.get('FileName', 'unknown')}", f"Source dataset: {j.get('source', 'unknown')}", f"Trust score: {j.get('hashlookup:trust', 'n/a')}"]
    if j.get("KnownMalicious"):
        return [F("CIRCL hashlookup", "Flagged as known malicious", "\n".join(d) + f"\nReason: {j['KnownMalicious']}", "high")]
    return [F("CIRCL hashlookup", "Known file (commonly seen software)", "\n".join(d))]


def _site_github(u):
    r = http_get(f"https://api.github.com/users/{u}", headers={"Accept": "application/vnd.github+json"})
    if r.status_code == 404:
        return None
    check(r, "GitHub")
    j = jget(r, "GitHub")
    return f"{j.get('html_url')}\nName: {j.get('name')}  Company: {j.get('company')}  Location: {j.get('location')}\nRepos: {j.get('public_repos')}  Followers: {j.get('followers')}  Joined: {str(j.get('created_at'))[:10]}\nBio: {j.get('bio')}"


def _site_gitlab(u):
    r = http_get("https://gitlab.com/api/v4/users", params={"username": u})
    check(r, "GitLab")
    j = jget(r, "GitLab")
    return f"{j[0].get('web_url')}\nName: {j[0].get('name')}" if j else None


def _site_keybase(u):
    r = http_get("https://keybase.io/_/api/1.0/user/lookup.json", params={"usernames": u, "fields": "basics,profile"})
    check(r, "Keybase")
    them = (jget(r, "Keybase").get("them") or [None])[0]
    return f"https://keybase.io/{u}\nName: {(them.get('profile') or {}).get('full_name')}" if them else None


def _site_docker(u):
    r = http_get(f"https://hub.docker.com/v2/users/{u}/")
    if r.status_code == 404:
        return None
    check(r, "Docker Hub")
    j = jget(r, "Docker Hub")
    return f"https://hub.docker.com/u/{u}\nName: {j.get('full_name')}  Location: {j.get('location')}  Joined: {str(j.get('date_joined'))[:10]}"


def _site_devto(u):
    r = http_get("https://dev.to/api/users/by_username", params={"url": u})
    if r.status_code == 404:
        return None
    check(r, "DEV")
    j = jget(r, "DEV")
    return f"https://dev.to/{u}\nName: {j.get('name')}  Joined: {j.get('joined_at')}"


def _site_hn(u):
    r = http_get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    check(r, "Hacker News")
    j = jget(r, "Hacker News")
    return f"https://news.ycombinator.com/user?id={u}\nKarma: {j.get('karma')}" if j else None


USER_SITES = {"GitHub": _site_github, "GitLab": _site_gitlab, "Keybase": _site_keybase,
              "Docker Hub": _site_docker, "DEV Community": _site_devto, "Hacker News": _site_hn}


def username_check(ttype, target):
    def one(item):
        name, fn = item
        try:
            return name, fn(target), None
        except ProviderError as e:
            return name, None, str(e)
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as e:
            return name, None, f"{name}: {type(e).__name__}"
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(one, USER_SITES.items()))
    out, found, missing, errors = [], [], [], []
    for name, info, err in results:
        if err:
            errors.append(err)
        elif info:
            found.append(name)
            out.append(F(name, f"Profile found on {name}", info))
        else:
            missing.append(name)
    out.insert(0, F("Username check", f"Found on {len(found)} of {len(USER_SITES)} public sources",
                    ("Found: " + ", ".join(found) if found else "No profile found.") +
                    ("\nNot found: " + ", ".join(missing) if missing else "") +
                    "\nOnly a few public APIs are checked, so this is NOT exhaustive. The same handle on different sites may be different people."))
    for e in errors:
        out.append(F("Username check", "Source unavailable", e, "info", "error"))
    return out


DISPOSABLE = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com", "trashmail.com",
              "throwawaymail.com", "sharklasers.com", "getnada.com", "maildrop.cc", "dispostable.com", "temp-mail.org", "fakeinbox.com"}


def email_check(ttype, target):
    dom = host_of("email", target)
    out = [F("E-mail", "Syntax is valid", f"Local part and domain ({dom}) are well-formed.", provenance="system")]
    try:
        mx = [a.to_text() for a in _resolver().resolve(dom, "MX")]
        out.append(F("E-mail", "Domain accepts mail (MX found)", "\n".join(mx[:6])))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        out.append(F("E-mail", "No MX records", f"{dom} does not publish mail servers; it likely cannot receive e-mail.", "medium"))
    except dns.exception.Timeout:
        out.append(F("E-mail", "MX lookup failed", "DNS timed out.", "info", "error"))
    if dom in DISPOSABLE:
        out.append(F("E-mail", "Disposable e-mail provider", f"{dom} is a known throw-away mail service.", "medium"))
    h = hashlib.md5(target.lower().encode()).hexdigest()
    g = http_get(f"https://gravatar.com/avatar/{h}", params={"d": "404", "s": 64}, timeout=10)
    if g.status_code == 200:
        out.append(F("Gravatar", "Gravatar profile exists", f"The address has a public Gravatar (https://gravatar.com/{h}). This means the e-mail has been used to sign up for some web service."))
    elif g.status_code == 404:
        out.append(F("Gravatar", "No Gravatar", "No Gravatar is registered for this address."))
    r = http_get("https://api.github.com/search/users", headers={"Accept": "application/vnd.github+json"}, params={"q": f"{target} in:email"}, timeout=12)
    if r.status_code == 200:
        items = jget(r, "GitHub").get("items", [])
        if items:
            out.append(F("GitHub", "GitHub account(s) list this public e-mail", "\n".join(i.get("html_url", "") for i in items[:5])))
        else:
            out.append(F("GitHub", "No GitHub account with this public e-mail", "Only matches e-mails users made public."))
    return out


# ---------------------------------------------------------------- sources that need your own API key
def virustotal(ttype, target):
    path = {"domain": f"domains/{target}", "ip": f"ip_addresses/{target}", "hash": f"files/{target}",
            "url": "urls/" + base64.urlsafe_b64encode(target.encode()).decode().strip("=")}[ttype]
    r = http_get("https://www.virustotal.com/api/v3/" + path, headers={"x-apikey": key("VIRUSTOTAL_API_KEY")}, timeout=20)
    if r.status_code == 404:
        return [F("VirusTotal", "Not found in VirusTotal", "VirusTotal has no record. This does not mean the indicator is safe.")]
    check(r, "VirusTotal")
    a = jget(r, "VirusTotal").get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    mal, sus, total = st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
    sev = "critical" if mal >= 10 else "high" if mal >= 3 else "medium" if (mal or sus) else "info"
    d = [f"Malicious: {mal}  Suspicious: {sus}  Harmless: {st.get('harmless', 0)}  Undetected: {st.get('undetected', 0)}",
         f"Community reputation: {a.get('reputation', 'n/a')}"]
    if ttype == "hash":
        d += [f"File type: {a.get('type_description', '?')}", f"Name: {a.get('meaningful_name', '?')}"]
    return [F("VirusTotal", f"{mal} of {total} engines flag this as malicious", "\n".join(d), sev)]


def abuseipdb(ttype, target):
    r = http_get("https://api.abuseipdb.com/api/v2/check", headers={"Key": key("ABUSEIPDB_API_KEY")},
                 params={"ipAddress": target, "maxAgeInDays": 90}, timeout=15)
    check(r, "AbuseIPDB")
    d = jget(r, "AbuseIPDB").get("data", {})
    s = d.get("abuseConfidenceScore", 0)
    sev = "high" if s >= 75 else "medium" if s >= 25 else "low" if s > 0 else "info"
    return [F("AbuseIPDB", f"Abuse confidence {s}%", f"Reports (90 days): {d.get('totalReports', 0)} from {d.get('numDistinctUsers', 0)} users\n"
              f"ISP: {d.get('isp')}  Usage: {d.get('usageType')}  Country: {d.get('countryCode')}\nLast reported: {d.get('lastReportedAt')}", sev)]


def shodan_host(ttype, target):
    r = http_get(f"https://api.shodan.io/shodan/host/{target}", params={"key": key("SHODAN_API_KEY")}, timeout=20)
    if r.status_code == 404:
        return [F("Shodan", "No information available", "Shodan has no record for this host.")]
    check(r, "Shodan")
    j = jget(r, "Shodan")
    svc = [f"{x.get('port')}/{x.get('transport', 'tcp')} {x.get('product', '')} {x.get('version', '')}".strip() for x in j.get("data", [])]
    out = [F("Shodan", f"{len(svc)} services indexed", f"Org: {j.get('org')}  OS: {j.get('os')}\n" + "\n".join(svc[:20]))]
    if j.get("vulns"):
        out.append(F("Shodan", f"{len(j['vulns'])} vulnerabilities listed", ", ".join(list(j["vulns"])[:20]), "high"))
    return out


def otx(ttype, target):
    kind = {"domain": "domain", "ip": "IPv6" if ":" in target else "IPv4", "url": "url", "hash": "file"}[ttype]
    r = http_get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(target, safe='')}/general",
                 headers={"X-OTX-API-KEY": key("OTX_API_KEY")}, timeout=20)
    if r.status_code == 404:
        return [F("AlienVault OTX", "Not found in OTX", "")]
    check(r, "AlienVault OTX")
    n = jget(r, "AlienVault OTX").get("pulse_info", {}).get("count", 0)
    return [F("AlienVault OTX", f"Mentioned in {n} threat pulses", "Pulses are community-submitted reports; quality varies.",
              "medium" if n >= 3 else "low" if n else "info")]


@dataclass
class Provider:
    id: str
    name: str
    types: tuple
    fn: str
    kind: str          # free | key | optional-key
    env: str | None
    desc: str

    def run(self, ttype, target):
        return getattr(sys.modules[__name__], self.fn)(ttype, target)

    def configured(self):
        return True if self.env is None else bool(key(self.env))


REGISTRY = [
    Provider("dns", "DNS", ("domain", "url"), "dns_lookup", "free", None, "A/AAAA/MX/NS/TXT, SPF and DMARC"),
    Provider("rdap_domain", "RDAP (domain)", ("domain", "url", "email"), "rdap_domain", "free", None, "Registrar, dates, nameservers"),
    Provider("crtsh", "Certificate Transparency", ("domain",), "crtsh", "free", None, "Hostnames from public certificates (crt.sh)"),
    Provider("rdap_ip", "RDAP (IP)", ("ip",), "rdap_ip", "free", None, "Network owner and allocation"),
    Provider("geoip", "GeoIP", ("ip",), "geoip", "free", None, "Approximate location and ASN"),
    Provider("rdns", "Reverse DNS", ("ip",), "reverse_dns", "free", None, "PTR record"),
    Provider("internetdb", "Shodan InternetDB", ("ip",), "internetdb", "free", None, "Open ports, CVEs and tags (no key)"),
    Provider("urlscan", "urlscan.io", ("domain", "ip", "url"), "urlscan", "optional-key", "URLSCAN_API_KEY", "Existing public scans (never submits)"),
    Provider("hashlookup", "CIRCL hashlookup", ("hash",), "hashlookup", "free", None, "Known-file dataset"),
    Provider("username", "Username check", ("username",), "username_check", "free", None, "GitHub, GitLab, Keybase, Docker Hub, DEV, Hacker News"),
    Provider("email", "E-mail checks", ("email",), "email_check", "free", None, "MX, disposable domain, Gravatar, GitHub"),
    Provider("virustotal", "VirusTotal", ("domain", "ip", "url", "hash"), "virustotal", "key", "VIRUSTOTAL_API_KEY", "Multi-engine reputation"),
    Provider("abuseipdb", "AbuseIPDB", ("ip",), "abuseipdb", "key", "ABUSEIPDB_API_KEY", "Abuse reports for an IP"),
    Provider("shodan", "Shodan", ("ip",), "shodan_host", "key", "SHODAN_API_KEY", "Full host data (key and eligible plan)"),
    Provider("otx", "AlienVault OTX", ("domain", "ip", "url", "hash"), "otx", "key", "OTX_API_KEY", "Threat pulses"),
]
