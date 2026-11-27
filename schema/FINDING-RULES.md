# Finding record: cross-field rules (enforced by `kt/finding.py`)

The JSON Schema (`finding-record.schema.json`) fixes the shape. These rules fix the meaning
(SPEC.md §3.1 and §8):

| # | Rule |
|---|---|
| R1 | Required sources per item type must be listed with `required: true` (package: `osv` + `kings_taster_list`; repo: `github_api` + `kings_taster_list`; link: `kings_taster_list` + `rdap` + `safe_browsing`). Nothing else may be `required: true`. Each source appears once. |
| R2 | If any required source isn't `ok`, the result is `unknown` (or `block`, which always wins). The matching reason must be present: `rate_limited` for 403/429, `no_link_source` for a link with no reputation source set up, `check_failed` otherwise; a failed list file needs `stale_list`, `unverified_list`, `check_failed`, `paused` or `update_required`. |
| R3 | Precedence Block > Unknown > Caution > No known reports. Unknown-class reasons (`check_failed`, `no_link_source`, `stale_list`, `unverified_list`, `injection_seen`, `paused`, `update_required`, `rate_limited`) force `unknown` unless the result is `block`. Caution-class reasons (`vulnerable_version`, `new_domain`, `no_rdap`, `lookalike`, `install_scripts`, `retired_entry`, `source_build_required`, `pending_review`) forbid `no_known_reports`. `block` ⇔ `malicious_match`. `pending_review` never appears with `malicious_match` (popular names are held at Caution). |
| R4 | `block`, `vulnerable_version`, `retired_entry` and `pending_review` need `matched_entries`. `fixed_version` only with `vulnerable_version` (null allowed only if the explanation says "no fixed version"). |
| R5 | `mode: checker` needs `checker_sha256`; `checklist` needs null. `checker_failed` means the bot fell back to `checklist`; it is informational and doesn't change the result by itself. |
| R6 | `explanation` starts with the fixed §3.1 prefix for the result ("Block.", "Caution.", "Unknown.", "No known reports."), and a clean answer is exactly `No known reports. Checked against <source> (<date>), … on <date>.`; word checks run after NFKC folding with invisible characters removed, and such characters are refused; never says "safe"/"guaranteed" (the product name "Safe Browsing" and Google's exact required notice are the only exceptions); "Advisory provided by Google" only when Safe Browsing was used; URLs only to official source hosts (github.com only for advisories and this repo; no dot, empty or encoded path segments); never contains the refanged indicator or its bare host; no control characters. |
| R7 | `indicator_defanged`: packages `npm:`/`pypi:` name[@version]; repos `github:owner/repo`; links `hxxp(s)://` with every host dot written `[.]`; never a live URL. |

There are no free-text, handle or location fields anywhere (all objects are `additionalProperties: false`).

Also: duplicate JSON keys, NaN/Infinity and deep nesting make a record unreadable; every pattern is anchored so a trailing newline never passes; `matched_entries[].source_url` gets the same official-link check as explanation URLs.
