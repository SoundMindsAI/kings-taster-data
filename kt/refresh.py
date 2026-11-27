"""Daily list-refresh skill helpers (SPEC.md §4B). Never contacts the network."""
import json
import os
import posixpath
import re
import shutil

from .common import parse_time, sha256_file, utc_now
from . import verify as KV

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-list-refresh.md")
ROUTINE_PATH = os.path.join(ROOT, "routines", "kings-taster-list-refresh.md")
ROUTINE_LINE = "Run kings-taster-list-refresh."
WORD_CAP = 200
COMMAND_LINE_CAP = 40
STALE_HOURS = 48
LIST_PATH_PREFIX = "/SoundMindsAI/kings-taster-data/releases/download/"
LATEST_URL = "https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"
BANNED = re.compile(r"\bsafe(ly|ty)?\b(?!\s+browsing)|guarantee", re.IGNORECASE)
SAFE_EXCEPTIONS = ('Never say "safe"',)


def skill_text():
    with open(SKILL_PATH, encoding="utf-8") as f:
        return f.read()


def split_skill(text=None):
    text = text if text is not None else skill_text()
    start = text.index("<!-- commands -->")
    end = text.index("<!-- /commands -->")
    return text[:start], text[start:end]


def word_count(body):
    return len(body.split())


def command_line_count(commands):
    return len(commands.strip().splitlines())


def routine_line():
    with open(ROUTINE_PATH, encoding="utf-8") as f:
        return f.read().strip()


def _unquote_path(value, times=4):
    out = value or ""
    for _ in range(times):
        nxt = re.sub(r"%([0-9A-Fa-f]{2})",
                     lambda m: bytes.fromhex(m.group(1)).decode("latin-1"), out)
        if nxt == out:
            break
        out = nxt
    return out


def _has_dotdot(value):
    raw = value or ""
    lower = raw.lower()
    if ".." in raw or "%2e%2e" in lower or "%2e." in lower or ".%2e" in lower or "%252e" in lower:
        return True
    return False


def list_url_allowed(url, list_redirect=False):
    """True only for the list-file download hosts and path prefix."""
    raw = url or ""
    if "://" in raw:
        rest = raw.split("://", 1)[1]
        host, _, path = rest.partition("/")
        path = "/" + path.split("?", 1)[0].split("#", 1)[0]
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        host = host.split(":", 1)[0].lower()
    else:
        return False
    if list_redirect:
        return host in ("github.com", "release-assets.githubusercontent.com")
    if host != "github.com":
        return False
    if _has_dotdot(path) or _has_dotdot(_unquote_path(path)):
        return False
    decoded = _unquote_path(path)
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith(LIST_PATH_PREFIX):
        return False
    parts = [p for p in normalized[len(LIST_PATH_PREFIX):].split("/") if p]
    return len(parts) >= 2 and ".." not in parts


class LocalFetcher:
    """Test double: copies files from a local directory. Never contacts the network."""

    def __init__(self, source_dir):
        self.source_dir = source_dir
        self.gets = []

    def fetch(self, url, dest):
        self.gets.append(url)
        if not list_url_allowed(url) and not url.endswith(".sig"):
            # signatures share the same path rules
            if not list_url_allowed(url[:-4] if url.endswith(".sig") else url):
                raise ValueError("injection_seen")
        name = url.rsplit("/", 1)[-1]
        src = os.path.join(self.source_dir, name)
        if not os.path.isfile(src):
            raise FileNotFoundError(name)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        shutil.copyfile(src, dest)
        return {"url": url, "ok": True}


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _file_sha(path):
    return sha256_file(path) if os.path.isfile(path) else None


def cached_shard_names(cache_dir):
    if not os.path.isdir(cache_dir):
        return []
    return sorted(n for n in os.listdir(cache_dir)
                  if n.startswith("shard-") and n.endswith(".json"))


def refresh(cache_dir, source_dir, *, fetcher=None, allowed_signers=None,
            state=None, now=None, update_state=True, require_shards=False):
    """Refresh the cached list from a local source directory. Never uses the network.

    `source_dir` stands in for the signed release the fetcher would download.
    Returns a dict: ok, silent, changed, fetched, failed, lines.
    """
    now = parse_time(now) if isinstance(now, str) else (now or utc_now())
    fetcher = fetcher or LocalFetcher(source_dir)
    allowed = allowed_signers or os.path.join(ROOT, "config", "allowed_signers")
    os.makedirs(cache_dir, exist_ok=True)
    work = os.path.join(cache_dir, ".incoming")
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)

    result = {"ok": False, "silent": False, "changed": False, "fetched": [],
              "failed": None, "lines": []}

    def fail(reason, detail):
        result["failed"] = reason
        result["lines"] = [
            "List refresh failed: %s." % reason,
            detail,
            "The last good cache was kept.",
        ][:3]
        shutil.rmtree(work, ignore_errors=True)
        return result

    try:
        latest_url = LATEST_URL
        if not list_url_allowed(latest_url):
            return fail("injection_seen", "The download host was not allowed.")
        fetcher.fetch(latest_url, os.path.join(work, "latest.json"))
        fetcher.fetch(latest_url + ".sig", os.path.join(work, "latest.json.sig"))
        result["fetched"].append("latest.json")
    except ValueError:
        return fail("injection_seen", "The download host was not allowed.")
    except (OSError, FileNotFoundError):
        return fail("check_failed", "latest.json could not be fetched.")

    # Need the tag to fetch manifest from the dated release, but first compare hashes.
    try:
        incoming_latest = _read_json(os.path.join(work, "latest.json"))
        incoming_sha = _file_sha(os.path.join(work, "latest.json"))
    except (OSError, ValueError, KeyError):
        return fail("unverified_list", "latest.json could not be read.")

    cached_latest_path = os.path.join(cache_dir, "latest.json")
    cached_sha = _file_sha(cached_latest_path)
    cached_manifest_sha = _file_sha(os.path.join(cache_dir, "manifest.json"))

    tag = incoming_latest.get("tag")
    if not isinstance(tag, str) or not tag.startswith("kt-"):
        return fail("unverified_list", "latest.json has no release tag.")
    base = "https://github.com/SoundMindsAI/kings-taster-data/releases/download/%s/" % tag

    need_manifest = True
    if cached_sha and cached_sha == incoming_sha and os.path.isfile(os.path.join(cache_dir, "manifest.json")):
        need_manifest = False
        try:
            cached = _read_json(cached_latest_path)
            gen = parse_time(cached["generated_at"])
            if (now - gen).total_seconds() > STALE_HOURS * 3600:
                shutil.rmtree(work, ignore_errors=True)
                return fail("stale_list", "The cached list is older than 48 hours.")
        except (OSError, ValueError, KeyError):
            pass
        else:
            shutil.rmtree(work, ignore_errors=True)
            result["ok"] = True
            result["silent"] = True
            result["changed"] = False
            result["tag"] = cached.get("tag") or tag
            result["generated_at"] = cached.get("generated_at")
            return result

    signed = ("manifest.json", "iocs.json", "conformance.json", "stats.json")
    if need_manifest:
        try:
            for name in signed:
                fetcher.fetch(base + name, os.path.join(work, name))
                fetcher.fetch(base + name + ".sig", os.path.join(work, name + ".sig"))
                result["fetched"].append(name)
        except (OSError, FileNotFoundError, ValueError):
            return fail("check_failed", "A signed release file could not be fetched.")
    else:
        for name in signed:
            for fn in (name, name + ".sig"):
                src = os.path.join(cache_dir, fn)
                if os.path.isfile(src):
                    shutil.copyfile(src, os.path.join(work, fn))

    # Copy cached shards into the work dir, then refetch only those that changed.
    try:
        manifest = _read_json(os.path.join(work, "manifest.json"))
    except (OSError, ValueError):
        return fail("unverified_list", "manifest.json could not be read.")
    listed = {s["file"]: s for s in (manifest.get("shards") or []) if "file" in s}
    for name in cached_shard_names(cache_dir):
        shutil.copyfile(os.path.join(cache_dir, name), os.path.join(work, name))
        info = listed.get(name)
        if not info:
            continue
        current = _file_sha(os.path.join(work, name))
        if current != info.get("sha256"):
            try:
                fetcher.fetch(base + name, os.path.join(work, name))
                result["fetched"].append(name)
            except (OSError, FileNotFoundError, ValueError):
                return fail("check_failed", "A cached shard could not be refetched.")

    # Signed files needed by the official verifier must be present if we have them in the source.
    for name in ("iocs.json", "conformance.json", "stats.json"):
        if not os.path.isfile(os.path.join(work, name)):
            src = os.path.join(source_dir, name)
            sig = src + ".sig"
            if os.path.isfile(src):
                # These are not fetched over the list-host rules from GitHub in this helper
                # unless the fetcher can see them. Copy from the provided release dir.
                shutil.copyfile(src, os.path.join(work, name))
                if os.path.isfile(sig):
                    shutil.copyfile(sig, os.path.join(work, name + ".sig"))

    try:
        now_val = now
        code, line = KV.verify_release(
            work, allowed, state=state, update_state=update_state,
            now=now_val, max_age_hours=STALE_HOURS, require_shards=require_shards,
        )
    except KV.VerifyError as e:
        return fail("unverified_list", str(e)[:200])
    except (OSError, ValueError, KeyError) as e:
        return fail("unverified_list", type(e).__name__)
    if code == 5:
        return fail("stale_list", line)
    if code not in (0, 3):  # 3 is paused: the file still verifies
        return fail("unverified_list", line)

    incoming_manifest_sha = _file_sha(os.path.join(work, "manifest.json"))
    changed = (cached_sha != incoming_sha) or (cached_manifest_sha != incoming_manifest_sha) or any(
        n.startswith("shard-") for n in result["fetched"])
    # Promote the incoming files into the cache (do not delete uncached shards we already had
    # if they still match; replace only what we have in work).
    for name in os.listdir(work):
        src = os.path.join(work, name)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(cache_dir, name))
    shutil.rmtree(work, ignore_errors=True)

    result["ok"] = True
    result["changed"] = bool(changed)
    result["silent"] = True  # success is silent, even when the list was updated
    result["lines"] = []
    result["tag"] = tag
    result["generated_at"] = incoming_latest.get("generated_at")
    return result


def body_banned_words(body):
    text = body
    for exc in SAFE_EXCEPTIONS:
        text = text.replace(exc, "")
    return bool(BANNED.search(text))
