"""Sharded list (SPEC.md §6.5): split iocs.json into shards and describe them in a signed manifest.

A shard holds the entries of one group (npm, pypi, kev, or one other entry type), optionally narrowed by the
first bytes of SHA-256(match_key). The group comes from the match_key's prefix, so a client can pick the one
shard it needs from the item alone. manifest.json lists every shard's file, SHA-256, size, gzipped size and
entry counts; the manifest is signed, and each shard is pinned by its SHA-256 in it.
"""
import gzip
import hashlib
import os

from .common import canonical_json, loads_strict, sha256_bytes

MATCH_KEY_GROUPS = (("npm:", "npm"), ("pypi:", "pypi"), ("cve:", "kev"), ("domain:", "domain"),
                    ("url-sha256:", "url"), ("ip:", "ip"), ("hash:", "hash"), ("github:", "repo_owner"))
GROUPS = tuple(g for _, g in MATCH_KEY_GROUPS)
ALLOWED_PREFIX_BYTES = (0, 1)  # 2 bytes would need 65,536 shards, over the release asset limit
DEFAULT_PREFIX_BYTES = {"npm": 1, "pypi": 1}  # every other group (kev included) is a single shard


class ShardError(Exception):
    pass


def group_of(match_key):
    for prefix, group in MATCH_KEY_GROUPS:
        if match_key.startswith(prefix):
            return group
    raise ShardError("match_key has no known group prefix")


def bucket_of(match_key, prefix_bytes):
    if prefix_bytes == 0:
        return None
    return hashlib.sha256(match_key.encode("utf-8")).hexdigest()[:2 * prefix_bytes]


def shard_name(group, bucket):
    return group if bucket is None else "%s-%s" % (group, bucket)


def shard_file(name):
    return "shard-%s.json" % name


def shard_for(match_key, groups):
    """The file name of the shard that holds match_key, given the manifest's `groups` map."""
    g = group_of(match_key)
    return shard_file(shard_name(g, bucket_of(match_key, groups[g]["prefix_bytes"])))


def gzip_size(b):
    return len(gzip.compress(b, compresslevel=9, mtime=0))


def looks_like_shard_filename(name):
    """True for shard-*.json and for hidden or differently cased variants (.shard-*, SHARD-*, Shard-*)."""
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    base = name[1:] if name.startswith(".") else name
    return base.lower().startswith("shard-")


def prefix_config(limits):
    cfg = dict(DEFAULT_PREFIX_BYTES)
    cfg.update((limits.get("shards") or {}).get("prefix_bytes", {}))
    out = {}
    for g in GROUPS:
        n = cfg.get(g, 0)
        if n not in ALLOWED_PREFIX_BYTES:
            raise ShardError("config: prefix_bytes for %s must be one of %s" % (g, ALLOWED_PREFIX_BYTES))
        out[g] = n
    if set(cfg) - set(GROUPS):
        raise ShardError("config: prefix_bytes names an unknown group")
    return out


def _all_buckets(n):
    if n == 0:
        return [None]
    return ["%0*x" % (2 * n, i) for i in range(256 ** n)]


def build_shards(iocs, limits):
    """Returns (manifest dict, {file name: canonical bytes}). Raises ShardError if a cap is exceeded."""
    caps = (limits.get("shards") or {})
    max_shard_gz = caps["max_shard_gzip_bytes"]
    max_manifest = caps["max_manifest_bytes"]
    prefix = prefix_config(limits)
    buckets = {}
    for g in GROUPS:
        for b in _all_buckets(prefix[g]):
            buckets[shard_name(g, b)] = {"group": g, "bucket": b, "entries": [], "revoked": []}
    for e in iocs["entries"]:
        g = group_of(e["match_key"])
        buckets[shard_name(g, bucket_of(e["match_key"], prefix[g]))]["entries"].append(e)
    for r in iocs["revoked_entries"]:
        g = group_of(r["match_key"])
        buckets[shard_name(g, bucket_of(r["match_key"], prefix[g]))]["revoked"].append(r)
    files, rows = {}, []
    by_group, by_type = {}, {}
    for name in sorted(buckets):
        s = buckets[name]
        doc = {"file_type": "shard", "schema_version": 1, "generated_at": iocs["generated_at"], "tag": iocs["tag"],
               "shard": name, "group": s["group"], "bucket": s["bucket"],
               "entries": sorted(s["entries"], key=lambda e: e["id"]),
               "revoked_entries": sorted(s["revoked"], key=lambda r: r["id"])}
        b = canonical_json(doc)
        gz = gzip_size(b)
        if gz > max_shard_gz:
            raise ShardError("shard %s is %d bytes gzipped, over the %d cap; raise its prefix length" % (name, gz, max_shard_gz))
        types = {}
        for e in s["entries"]:
            types[e["type"]] = types.get(e["type"], 0) + 1
            by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        by_group[s["group"]] = by_group.get(s["group"], 0) + len(s["entries"])
        files[shard_file(name)] = b
        rows.append({"name": name, "file": shard_file(name), "group": s["group"], "bucket": s["bucket"],
                     "sha256": sha256_bytes(b), "bytes": len(b), "gzip_bytes": gz,
                     "entries": len(s["entries"]), "revoked": len(s["revoked"]), "by_type": types})
    manifest = {"file_type": "manifest", "schema_version": 1, "generated_at": iocs["generated_at"], "tag": iocs["tag"],
                "shard_key": "sha256(match_key)",
                "groups": {g: {"prefix_bytes": prefix[g]} for g in GROUPS},
                "caps": {"manifest_bytes": max_manifest, "shard_gzip_bytes": max_shard_gz},
                "counts": {"entries": len(iocs["entries"]), "revoked": len(iocs["revoked_entries"]),
                           "shards": len(rows), "by_group": by_group, "by_type": by_type},
                "shards": rows}
    mb = canonical_json(manifest)
    if len(mb) > max_manifest:
        raise ShardError("manifest.json is %d bytes, over the %d cap" % (len(mb), max_manifest))
    return manifest, files


def validate_shards(d, manifest, iocs=None, require_all=True, limits_caps=None):
    """Check shard files in d against a parsed manifest. With iocs, also check that the shards hold exactly
    iocs.json's entries and revocations, each in the right shard. Returns a list of problems."""
    errors = []
    caps = manifest["caps"]
    if limits_caps:
        if caps != limits_caps:
            errors.append("manifest: caps differ from config/limits.json")
    groups = manifest["groups"]
    if set(groups) != set(GROUPS):
        return errors + ["manifest: groups must be exactly %s" % list(GROUPS)]
    expected = sorted(shard_name(g, b) for g in GROUPS for b in _all_buckets(groups[g]["prefix_bytes"]))
    names = [s["name"] for s in manifest["shards"]]
    if names != expected:
        return errors + ["manifest: shard list does not match the groups and prefix lengths"]
    if manifest["counts"]["shards"] != len(names):
        errors.append("manifest: shard count mismatch")
    listed = {s["file"] for s in manifest["shards"]}
    extra = [n for n in os.listdir(d) if looks_like_shard_filename(n) and n not in listed]
    if extra:
        errors.append("release dir holds %d shard file(s) the manifest doesn't list" % len(extra))
    total, by_group, by_type, revoked_total = 0, {}, {}, 0
    seen_ids, seen_rev = {}, {}
    for s in manifest["shards"]:
        if s["file"] != shard_file(s["name"]) or s["name"] != shard_name(s["group"], s["bucket"]):
            errors.append("manifest: shard %s has a bad file, group or bucket" % s["name"]); continue
        total += s["entries"]; revoked_total += s["revoked"]
        by_group[s["group"]] = by_group.get(s["group"], 0) + s["entries"]
        for t, n in s["by_type"].items():
            by_type[t] = by_type.get(t, 0) + n
        if sum(s["by_type"].values()) != s["entries"]:
            errors.append("manifest: shard %s per-type counts don't add up" % s["name"])
        if s["gzip_bytes"] > caps["shard_gzip_bytes"]:
            errors.append("manifest: shard %s is over the gzip cap" % s["name"])
        p = os.path.join(d, s["file"])
        if not os.path.exists(p):
            if require_all:
                errors.append("shard %s missing" % s["name"])
            continue
        with open(p, "rb") as f:
            b = f.read()
        if sha256_bytes(b) != s["sha256"] or len(b) != s["bytes"]:
            errors.append("shard %s hash/size mismatch" % s["name"]); continue
        gz = gzip_size(b)
        if gz > caps["shard_gzip_bytes"] or gz != s["gzip_bytes"]:
            errors.append("shard %s gzip size is wrong or over the cap" % s["name"]); continue
        try:
            doc = loads_strict(b)
        except ValueError:
            errors.append("shard %s is not JSON or has duplicate keys" % s["name"]); continue
        if not isinstance(doc, dict) or b != canonical_json(doc):
            errors.append("shard %s is not a canonical JSON object" % s["name"]); continue
        want = {"file_type", "schema_version", "generated_at", "tag", "shard", "group", "bucket", "entries",
                "revoked_entries"}
        if set(doc) != want or doc["file_type"] != "shard" or doc["schema_version"] != 1:
            errors.append("shard %s has the wrong fields or file_type" % s["name"]); continue
        if doc["generated_at"] != manifest["generated_at"] or doc["tag"] != manifest["tag"]:
            errors.append("shard %s generated_at/tag differ from the manifest" % s["name"])
        if (doc["shard"], doc["group"], doc["bucket"]) != (s["name"], s["group"], s["bucket"]):
            errors.append("shard %s name/group/bucket differ from the manifest" % s["name"])
        if len(doc["entries"]) != s["entries"] or len(doc["revoked_entries"]) != s["revoked"]:
            errors.append("shard %s entry counts differ from the manifest" % s["name"])
        types = {}
        for e in doc["entries"]:
            types[e.get("type")] = types.get(e.get("type"), 0) + 1
        if types != s["by_type"]:
            errors.append("shard %s per-type counts differ from the manifest" % s["name"])
        n = groups[s["group"]]["prefix_bytes"]
        for kind, rows, seen in (("entry", doc["entries"], seen_ids), ("revocation", doc["revoked_entries"], seen_rev)):
            for e in rows:
                mk = e.get("match_key", "")
                try:
                    right = group_of(mk) == s["group"] and bucket_of(mk, n) == s["bucket"]
                except ShardError:
                    right = False
                if not right:
                    errors.append("shard %s holds a %s that belongs in another shard" % (s["name"], kind)); break
                if e.get("id") in seen:
                    errors.append("shard %s repeats a %s id" % (s["name"], kind)); break
                seen[e.get("id")] = e
    c = manifest["counts"]
    if c["entries"] != total or c["by_group"] != {g: n for g, n in by_group.items()} or c["by_type"] != by_type \
            or c["revoked"] != revoked_total:
        errors.append("manifest: totals don't match the per-shard counts")
    if iocs is not None and not errors and require_all:
        if c["entries"] != len(iocs["entries"]) or c["revoked"] != len(iocs["revoked_entries"]):
            errors.append("manifest: totals differ from iocs.json")
        full = {e["id"]: e for e in iocs["entries"]}
        if set(full) != set(seen_ids) or any(full[i] != seen_ids[i] for i in full):
            errors.append("shards: entries differ from iocs.json")
        rev = {r["id"]: r for r in iocs["revoked_entries"]}
        if set(rev) != set(seen_rev) or any(rev[i] != seen_rev[i] for i in rev):
            errors.append("shards: revocations differ from iocs.json")
    return errors
