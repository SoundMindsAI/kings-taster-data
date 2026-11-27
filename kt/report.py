"""Print a short Markdown summary of build-report.json (counts and codes only, no indicator values)."""
import sys

from .common import read_json


def main(argv):
    r = read_json(argv[0])
    lines = ["### King's Taster build %s" % r["tag"], "",
             "- needs human review: **%s** %s" % ("yes" if r["needs_human"] else "no", ", ".join(r["breaker"])),
             "- added %d, removed %d, newly revoked %d" % (r["added"], r["removed"], r["newly_revoked"]),
             "- hold queue (popular names held at pending_review): %d" % len(r["hold_queue"]),
             "- sources: " + ", ".join("%s=%s" % kv for kv in sorted(r["sources"].items())),
             "- rejected upstream records: " + ", ".join("%s=%d" % kv for kv in sorted(r["rejected_upstream_records"].items())),
             "", "Unsigned. The owner signs and publishes with scripts/sign-and-release.sh --run-id <this run>."]
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
