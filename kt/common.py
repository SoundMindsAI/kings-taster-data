"""Shared helpers: time, hashing, defanging, match_key, name rules, HTTP evidence."""
import datetime as _dt
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request

ISO_Z = "%Y-%m-%dT%H:%M:%SZ"
USER_AGENT = "kings-taster-data-pipeline/1.0 (+https://github.com/SoundMindsAI/kings-taster-data)"

# Hosts the pipeline may fetch from. Nothing else, and no redirects.
FETCH_ALLOWLIST = {
    "www.cisa.gov",
    "osv-vulnerabilities.storage.googleapis.com",
}


def utc_now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def fmt_time(t):
    return t.astimezone(_dt.timezone.utc).strftime(ISO_Z)


def parse_time(s):
    """Parse an ISO-8601 UTC time (Z suffix, optional fraction) or a YYYY-MM-DD date."""
    if not isinstance(s, str):
        raise ValueError("time must be a string")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s, re.ASCII):
        return _dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,9})?(Z|[+-]00:00)", s, re.ASCII)
    if not m:
        raise ValueError("not an ISO UTC time: %r" % s[:40])
    return _dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=_dt.timezone.utc)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj):
    """Deterministic bytes for files we sign: sorted keys, 1-space-free, UTF-8, trailing newline."""
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


# ---- names and values -------------------------------------------------------

NPM_LEGACY_NAME = re.compile(r"^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*\Z")
PEP508_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])\Z", re.IGNORECASE)
VERSION = re.compile(r"^[A-Za-z0-9.+_!~-]{1,64}\Z")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,8}\Z")
MAL_ID = re.compile(r"^MAL-\d{4}-\d{1,8}\Z")
ALIAS_ID = re.compile(r"^(CVE-\d{4}-\d{4,8}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d{1,8}|MAL-\d{4}-\d{1,8}|OSV-\d{4}-\d{1,8})\Z")
ORIGIN_SOURCE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}\Z")
# Short labels such as KEV vendor/product: letters (any script), digits, limited punctuation.
SHORT_LABEL = re.compile(r"^(?!_)[\w.][\w .,&()+/'’:!–-]{0,119}\Z", re.UNICODE)
_SPACES = re.compile(r"[\s\u00a0\u2000-\u200b\u202f\u205f\u3000]+")


def clean_label(s):
    """Normalize spacing and validate a short label. Returns None if it can't be trusted."""
    if not isinstance(s, str):
        return None
    s = _SPACES.sub(" ", s).strip()
    if "://" in s or not SHORT_LABEL.match(s):
        return None
    return s


def valid_package_name(ecosystem, name):
    if not isinstance(name, str):
        return False
    if ecosystem == "npm":
        return len(name) <= 214 and bool(NPM_LEGACY_NAME.match(name))
    if ecosystem == "PyPI":
        return len(name) <= 200 and bool(PEP508_NAME.match(name))
    return False


def normalize_package(ecosystem, name):
    """Canonical package name used in match_key: npm lowercased, PyPI per PEP 503."""
    if ecosystem == "npm":
        return name.lower()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    raise ValueError("unsupported ecosystem")


ECO_PREFIX = {"npm": "npm", "PyPI": "pypi"}


def match_key(ioc_type, value, ecosystem=None):
    """SPEC.md §6.2: lowercased/IDNA form, or SHA-256 of the canonical value. Typed prefix added."""
    if ioc_type == "package":
        return "%s:%s" % (ECO_PREFIX[ecosystem], normalize_package(ecosystem, value))
    if ioc_type == "cve":
        return "cve:" + value.lower()
    if ioc_type == "domain":
        return "domain:" + value.rstrip(".").encode("idna").decode("ascii").lower()
    if ioc_type == "ip":
        return "ip:" + value.lower()
    if ioc_type == "hash":
        return "hash:" + value.lower()
    if ioc_type == "repo_owner":
        return "github:" + value.lower()
    if ioc_type == "url":
        # The caller must pass the canonical URL (C3 canonicalization rules).
        return "url-sha256:" + sha256_bytes(value.encode("utf-8"))
    raise ValueError("unsupported type")


def defang(ioc_type, value, ecosystem=None):
    if ioc_type == "package":
        return "%s:%s" % (ECO_PREFIX[ecosystem], value)
    if ioc_type in ("domain", "ip"):
        return value.replace(".", "[.]")
    if ioc_type == "url":
        m = re.match(r"^(https?)://([^/?#]*)(.*)\Z", value, re.IGNORECASE)
        if not m:
            raise ValueError("bad url")
        scheme = "hxxps" if m.group(1).lower() == "https" else "hxxp"
        return "%s://%s%s" % (scheme, m.group(2).replace(".", "[.]"), m.group(3).replace("://", "[://]"))
    if ioc_type == "repo_owner":
        return "github:" + value
    return value


# ---- HTTP with evidence -----------------------------------------------------

class FetchError(Exception):
    def __init__(self, msg, evidence):
        super().__init__(msg)
        self.evidence = evidence


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, dest_path, max_bytes, timeout=120):
    """GET an allowlisted HTTPS URL into dest_path. No redirects.

    Returns evidence: {url, http_status, response_sha256, bytes, last_modified, fetched_at}.
    Raises FetchError (with evidence) on any non-200, oversize, or disallowed host.
    """
    m = re.match(r"^https://([^/:?#]+)/", url)
    evidence = {"url": url, "http_status": None, "response_sha256": None, "bytes": 0,
                "last_modified": None, "fetched_at": fmt_time(utc_now())}
    if not m or m.group(1) not in FETCH_ALLOWLIST:
        raise FetchError("host not on the fetch allowlist", evidence)
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        evidence["http_status"] = e.code
        raise FetchError("HTTP %d" % e.code, evidence)
    except (urllib.error.URLError, OSError) as e:
        raise FetchError("network error: %s" % type(e).__name__, evidence)
    with resp:
        evidence["http_status"] = resp.status
        evidence["last_modified"] = resp.headers.get("Last-Modified")
        if resp.status != 200:
            raise FetchError("HTTP %d" % resp.status, evidence)
        h = hashlib.sha256()
        n = 0
        with open(dest_path, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                n += len(chunk)
                if n > max_bytes:
                    raise FetchError("response larger than %d bytes" % max_bytes, evidence)
                h.update(chunk)
                out.write(chunk)
    evidence["bytes"] = n
    evidence["response_sha256"] = h.hexdigest()
    return evidence


def write_json(path, obj):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical_json(obj))
    os.replace(tmp, path)


class DuplicateKeyError(ValueError):
    pass


def _no_dup_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError("duplicate JSON key")
        d[k] = v
    return d


def _no_constants(name):
    raise ValueError("NaN/Infinity are not JSON")


def loads_strict(data):
    """Parse JSON bytes/str, refusing duplicate keys, NaN/Infinity and absurd nesting (ValueError)."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        return json.loads(data, object_pairs_hook=_no_dup_pairs, parse_constant=_no_constants)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


def read_json(path):
    with open(path, "rb") as f:
        return loads_strict(f.read())
