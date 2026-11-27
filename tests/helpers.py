import datetime as dt
import glob
import json
import os
import shutil
import tempfile
import zipfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIX = os.path.join(REPO, "tests", "fixtures")


def save(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def tmpdir(testcase):
    d = tempfile.mkdtemp()
    testcase.addCleanup(shutil.rmtree, d, True)
    return d


def readb(path):
    with open(path, "rb") as f:
        return f.read()


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def make_root(tmp, **overrides):
    """A temp copy of config/review/conformance with fixture-sized limits."""
    root = os.path.join(tmp, "root")
    for d in ("config", "review", "conformance"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(root, d))
    limits = load(os.path.join(root, "config", "limits.json"))
    limits["min_entries"] = {"osv-npm": 1, "osv-pypi": 1, "cisa-kev": 1}
    limits.update(overrides.pop("limits", {}))
    save(os.path.join(root, "config", "limits.json"), limits)
    can = load(os.path.join(root, "config", "canaries.json"))
    can["upstream"]["cisa-kev"] = ["CVE-2026-103406"]
    save(os.path.join(root, "config", "canaries.json"), can)
    return root


def osv_zip(path, eco, extra=None, skip=()):
    with zipfile.ZipFile(path, "w") as z:
        for f in sorted(glob.glob(os.path.join(FIX, "recorded", "osv", eco, "*.json"))):
            if os.path.basename(f) in skip:
                continue
            z.write(f, os.path.basename(f))
        for name, rec in (extra or {}).items():
            z.writestr(name, rec if isinstance(rec, (str, bytes)) else json.dumps(rec))
    return path


def mal_record(rid, eco, name, origins=("kam193",), versions=("1.0.0",), published="2026-11-25T10:00:00Z",
               withdrawn=None, details="x"):
    rec = {"schema_version": "1.7.3", "id": rid, "published": published, "modified": published,
           "summary": "Malicious code in %s (%s)" % (name, eco), "details": details,
           "affected": [{"package": {"ecosystem": eco, "name": name}, "versions": list(versions)}],
           "database_specific": {"malicious-packages-origins": [{"source": o} for o in origins]}}
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def fetch_all(tmp, root, npm_extra=None, pypi_extra=None, kev_path=None, npm_skip=()):
    """Run the three fetchers on recorded fixtures; returns the sources dir."""
    from kt import fetch_kev, fetch_osv
    from kt.common import read_json
    limits = read_json(os.path.join(root, "config", "limits.json"))
    can = read_json(os.path.join(root, "config", "canaries.json"))
    src = os.path.join(tmp, "sources-%d" % len(os.listdir(tmp)))
    os.makedirs(src)
    fetch_osv.run("npm", os.path.join(src, "osv-npm.json"),
                  osv_zip(os.path.join(tmp, "npm-%s.zip" % os.path.basename(src)), "npm", npm_extra, npm_skip), limits, can)
    fetch_osv.run("PyPI", os.path.join(src, "osv-pypi.json"),
                  osv_zip(os.path.join(tmp, "pypi-%s.zip" % os.path.basename(src)), "PyPI", pypi_extra), limits, can)
    fetch_kev.run(os.path.join(src, "kev.json"),
                  kev_path or os.path.join(FIX, "recorded", "kev", "known_exploited_vulnerabilities.trimmed.json"),
                  limits, can)
    return src


T0 = dt.datetime(2026, 11, 27, 6, 17, 0, tzinfo=dt.timezone.utc)
T0_ISO = "2026-11-27T06:17:00Z"
