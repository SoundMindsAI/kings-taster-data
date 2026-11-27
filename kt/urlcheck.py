"""One URL/host parser shared by the check, refresh, finding and fetch code. No network.

Every helper refuses the same authority tricks: backslash, ';', tab, CR, LF, space,
userinfo ('@'), '?' or '#' in the authority, and any explicit port (even a bad one).
Callers keep their own path and host allowlists.
"""
import posixpath
import re
from urllib.parse import unquote, urlsplit

LIST_PATH_PREFIX = "/SoundMindsAI/kings-taster-data/releases/download/"
LIST_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})
# '[' and ']' are out: only DNS names are accepted. ':' is out: no explicit port.
_BAD_AUTHORITY = frozenset("\\;\t\r\n @?#:[]")
_WHITESPACE = frozenset(" \t\r\n")


def is_url(value):
    """True for a full URL or a '//host' reference."""
    return "://" in value or value.startswith("//")


def _raw_authority(url):
    rest = url.split("://", 1)[1] if "://" in url else url[2:]
    return rest.split("/", 1)[0]


def _check_authority(authority):
    if not authority or any(c in _BAD_AUTHORITY for c in authority):
        raise ValueError("bad authority")


def bare_host(value):
    """Lowercase a bare host argument, or raise ValueError if it is not a plain name."""
    _check_authority(value)
    return value.lower()


def split_url(url):
    """Return (scheme, hostname, path) or raise ValueError("unparsable" / "bad authority").

    The hostname is the one urlsplit reports and the raw authority must equal the
    netloc urlsplit parsed, so no parser can read a different host from the same text.
    """
    try:
        parts = urlsplit(url)
        parts.port  # a bad port such as ':-0' raises here
    except ValueError:
        raise ValueError("unparsable") from None
    authority = _raw_authority(url)
    _check_authority(authority)
    if url[0] <= " " or url[-1] <= " ":  # urlsplit trims these, so it would hide them
        raise ValueError("bad authority")
    if parts.netloc != authority:
        raise ValueError("bad authority")
    return parts.scheme, (parts.hostname or "").lower(), parts.path or "/"


def parse_https_url(url):
    """(hostname, path) for a plain https URL, else None."""
    if not isinstance(url, str) or not is_url(url):
        return None
    try:
        scheme, host, path = split_url(url)
    except ValueError:
        return None
    if scheme != "https":
        return None
    return host, path


def same_host(a, b):
    """True when both full URLs parse cleanly and name the same host (N3)."""
    try:
        return split_url(a)[1] == split_url(b)[1]
    except ValueError:
        return False


def _unquote_path(value, times=4):
    """Decode %XX sequences (any case) a few times, without a network library."""
    out = value or ""
    for _ in range(times):
        nxt = re.sub(r"%([0-9A-Fa-f]{2})",
                     lambda m: bytes.fromhex(m.group(1)).decode("latin-1"), out)
        if nxt == out:
            break
        out = nxt
    return out


def _has_dotdot(value):
    """True if value has a '..' path segment, including percent-encoded forms."""
    raw = value or ""
    lower = raw.lower()
    return (".." in raw or "%2e%2e" in lower or "%2e." in lower
            or ".%2e" in lower or "%252e" in lower)


def list_path_ok(path):
    """Only /SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>.

    The prefix is matched on segment boundaries. Any '..' (raw or encoded, any case) is refused.
    """
    if not path or _has_dotdot(path):
        return False
    decoded = _unquote_path(path)
    if _has_dotdot(decoded) or "\\" in decoded:
        return False
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith(LIST_PATH_PREFIX):
        return False
    parts = [p for p in normalized[len(LIST_PATH_PREFIX):].split("/") if p]
    return len(parts) >= 2 and not any(p in (".", "..") for p in parts)


def list_download_url_ok(url, list_redirect=False):
    """True only for an https list-file URL: github.com plus the list path, or a redirect host."""
    parsed = parse_https_url(url)
    if parsed is None:
        return False
    host, path = parsed
    if list_redirect:
        return host in LIST_HOSTS
    return host == "github.com" and list_path_ok(path)


def official_link_ok(url, allowed_hosts):
    """Return (problem, host, decoded_path); problem is None for a plain https link on an allowed host.

    Callers add their own path rules (for example github.com advisories only).
    """
    if "\\" in url or re.search(r"%2e|%2f|%5c", url, re.IGNORECASE):
        return "encoded dot, slash or backslash", None, None
    if any(c in _WHITESPACE for c in url):
        return "whitespace or control character", None, None
    try:
        scheme, host, path = split_url(url)
    except ValueError as e:
        return ("unparsable" if str(e) == "unparsable" else "not an official https host"), None, None
    if scheme != "https" or host not in allowed_hosts:
        return "not an official https host", None, None
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    segs = decoded.split("/")[1:]
    if any(s in (".", "..") for s in segs) or "" in segs[:-1]:
        return "dot or empty path segment", None, None
    return None, host, decoded
