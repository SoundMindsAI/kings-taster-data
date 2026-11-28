"""Lookalike-name check (SPEC.md §3.3). Offline, deterministic, standard library only.

A label is flagged when it is not itself a popular name and is one edit away from one
(both at least 5 characters) or equals one after a small fixed confusable fold. Only the
names in config/popular/ are compared. Run `python3 -E -s -m kt.lookalike KIND INDICATOR`.
"""
import re
import sys

MIN_LEN = 5
_IPV4 = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}\Z")
_PKG_IND = re.compile(r"^(npm|pypi):(@?[^@]+)(@.*)?\Z", re.IGNORECASE)
_REPO_IND = re.compile(r"^github:([^/]+)/([^/]+)\Z", re.IGNORECASE)
_FIELD = re.compile(r"^[a-z0-9@._/-]{1,256}\Z")


def fold(text):
    """Fixed confusable fold: 0->o, 1->l, then rn->m and vv->w until neither remains."""
    # One pass is enough: m and w cannot join with a neighbour to form a new rn or vv.
    return text.lower().replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")


def distance(a, b):
    """Damerau-Levenshtein distance (an adjacent transposition counts as one edit)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def match_label(label, popular):
    """The lexicographically first popular name the label looks like, or None.

    popular is an iterable of canonical popular names. A label that is itself popular,
    or has a non-ASCII character, is never flagged.
    """
    label = label.lower()
    if not label or not label.isascii():
        return None
    prepared = _prepare(popular)
    if label in prepared[0]:
        return None
    folded = fold(label)
    for name, fname in prepared[1]:
        if fname == folded:
            return name
        if len(label) >= MIN_LEN and abs(len(label) - len(name)) <= 1 and distance(label, name) <= 1:
            return name
    return None


_PREPARED = {}


def _prepare(popular):
    """(set of names, sorted [(name, folded)] of eligible names); cached per frozenset."""
    if isinstance(popular, frozenset) and popular in _PREPARED:
        return _PREPARED[popular]
    names = set(popular)
    eligible = [(n, fold(n)) for n in sorted(names) if len(n) >= MIN_LEN and n.isascii()]
    prepared = (names, eligible)
    if isinstance(popular, frozenset):
        _PREPARED.clear()
        _PREPARED[popular] = prepared
    return prepared


def popular_union(root=None):
    """Union of canonical names in config/popular/ (npm and PyPI). Raises OSError if unreadable, ValueError if empty."""
    from . import check
    return frozenset(name for _, name in check._popular_names(root))


def package_parts(item):
    """(canonical ecosystem or None, name) from the item fields or the npm:/pypi: indicator."""
    eco, name = item.get("ecosystem"), item.get("name")
    if not (eco and name):
        m = _PKG_IND.match(item.get("indicator_defanged") or "")
        if not m:
            return None, None
        eco, name = m.group(1), m.group(2)
    return {"npm": "npm", "pypi": "PyPI"}.get(str(eco).lower()), name


def package_ecosystem(item):
    """Return "npm", "PyPI", or None for a package item."""
    return package_parts(item)[0]


def _package_labels(item):
    from .common import normalize_package
    eco, name = package_parts(item)
    if eco is None:
        return []
    canon = normalize_package(eco, name)
    labels = [canon]
    if eco == "npm" and canon.startswith("@") and "/" in canon:
        labels.append(canon.split("/", 1)[1])
    return labels


def _repo_labels(item):
    owner, repo = item.get("owner"), item.get("repo")
    if not (owner and repo):
        m = _REPO_IND.match(item.get("indicator_defanged") or "")
        if not m:
            return []
        owner, repo = m.group(1), m.group(2)
    return [owner.lower(), repo.lower()]


def _link_labels(item):
    from . import checker_build, finding, urlcheck
    url = finding._refang(item.get("indicator_defanged") or "")
    try:
        host = urlcheck.split_url(checker_build.canonical_url(url))[1]
    except ValueError:
        return []
    if _IPV4.match(host):
        return []
    return host.split(".")[:-1]


def labels_for(item):
    """The labels to compare for an item (package, repo, or link); may be empty."""
    kind = item.get("item_type")
    if kind == "package":
        return _package_labels(item)
    if kind == "repo":
        return _repo_labels(item)
    if kind == "link":
        return _link_labels(item)
    return []


def check(item, root=None):
    """Return {"class": "clean"}, {"class": "lookalike", "label", "match"} or {"class": "check_failed"}."""
    try:
        eco = package_ecosystem(item) if item.get("item_type") == "package" else None
        if eco:
            from . import check as _check
            popular = _check.popular_for(eco, root)  # a package uses only its own list
        else:
            popular = popular_union(root)  # repo and link use both lists
    except (OSError, ValueError):
        return {"class": "check_failed"}
    for label in labels_for(item):
        hit = match_label(label, popular)
        if hit:
            return {"class": "lookalike", "label": label, "match": hit}
    return {"class": "clean"}


def main(argv):
    if len(argv) != 3 or argv[1] not in ("package", "repo", "link"):
        print("class check_failed")
        return 0
    res = check({"item_type": argv[1], "indicator_defanged": argv[2]})
    print("class %s" % res["class"])
    if res["class"] == "lookalike" and _FIELD.match(res["label"]) and _FIELD.match(res["match"]):
        print("label %s" % res["label"])
        print("match %s" % res["match"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
