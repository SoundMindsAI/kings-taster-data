# King's Taster ("the King's Poison Taster"): public specification

**Spec version 1.0, matches kings-taster-data release format `schema_version: 1` (first signed release: not yet published).**
This document is versioned. It is updated in the same pull request as any change to the release files, the
schemas or the pipeline, and the version line above says which release it describes.

King's Taster checks things you're about to download, install or click (a GitHub repo before a clone or pull,
an npm or PyPI package before install, and a link before you open it) and answers with one of four results,
each citing its sources and their dates. It never says "safe".

---

## 1. Design rules

- **No SoundMinds server.** Each installed bot asks official sources directly and checks this repo's signed
  list file. Nothing is sent to SoundMinds.
- **Strict answers.** Never "safe" or "guaranteed". A clean answer is "No known reports, checked against
  <sources> on <date>". Every verdict cites a source and a date. Any failed check means
  "Unknown, don't proceed".
- **Text-only template.** A Grok Bot template carries text (skills and routines as prose). Nothing runs at
  install. Checks are an AI following a fixed checklist with fixed commands, or an optional local checker the
  bot builds and the user approves (§5). The only deterministic code SoundMinds runs is this repo's pipeline,
  and it never receives user data.
- **Honesty line** (shown to users): King's Taster is an AI following a checklist against official sources.
  It can make mistakes or be tricked by what it reads. "No known reports" means nothing was found, not that
  it's safe. Your checks go from your bot to the sources listed, and to your bot's AI provider, never to
  SoundMinds. Any keys you add are visible to your bot's AI.
- Only the official template link on soundminds.ai is from us; copies from anywhere else are not.

## 2. Trust model

| Threat | Defense, and what's left |
|---|---|
| Prompt injection through a package name, IOC string, README, RDAP field or API response | Fixed extraction commands print only allowlisted, validated fields (IDs checked by regex, ISO dates, fixed values, booleans, versions). No free-text field reaches the AI. Raw responses go to a temp file the AI never reads. Any instruction-like or pattern-breaking value means Unknown (`injection_seen`). **Left:** an AI can still be fooled; we say so. |
| A malicious project's own files (lockfile, `.npmrc`, build backend) | Binary-only resolution, `.npmrc` ignored, the default registry set on the command line, nothing ever built. |
| A phishing link tuned to read clean | A domain under 30 days old, or with no RDAP record, gives Caution. A link with no link-reputation source set up gives Unknown. |
| Mass false alarms on popular packages | `vulnerable` entries never Block. A malicious entry on a popular name is held at Caution (`pending_review`) until a person approves it, and approval also needs two distinct upstream origins (§7.2). |
| Poisoning the pipeline | Only deterministic parsers of structured feeds; a circuit breaker on large changes, popular-name hits and carried-over sources; free text never copied. |
| Stolen signing key, repo takeover, rollback | The private key never touches CI. Detached OpenSSH signatures; the current and next public keys are pinned; `generated_at` must only move forward; `revoked_entries` only grows; fixed release-asset URLs; branch protection and CODEOWNERS. |
| A tampered local checker | The bot records the checker's SHA-256 at approval; if it changes, the bot falls back to checklist mode and asks again. |
| Stolen API keys | Host allowlist, no redirects, keys read from an environment variable only, and the AI is told never to print them. |

## 3. Results

### 3.1 Required sources, precedence and wording

| Item | Required | Optional |
|---|---|---|
| Package (npm or PyPI) | live OSV (with its canary passing) **and** a verified list file | a GitHub token |
| Repo (before clone or pull) | GitHub API metadata **and** a verified list file | a GitHub token |
| Link (or a file to download) | a verified list file **and** RDAP **and** at least one link-reputation source | none |

If a required source is missing or fails, the answer is Unknown. An optional source that isn't set up is listed
as "not set up".

**Precedence.** Every check runs, and the answer is the worst one: **Block, then Unknown, then Caution, then
No known reports.** A Block or Caution found anywhere is always shown, even when the overall answer is Unknown.
An unverifiable list file makes the overall answer Unknown; live OSV Blocks and Cautions still show, and
"No known reports" is impossible.

**Live OSV rule.** `MAL-` IDs and their aliases count as malicious (Block). Everything else counts as
vulnerable (Caution, "upgrade to ≥ X"). A live malicious hit on a popular (top-10k) name is held at
**Caution: "reported malicious by OSV, pending review"** until the list file carries an approved entry.

| Answer | Fixed wording (the voice may change, the meaning may not) |
|---|---|
| Block | "Block. <item> is listed as malicious by <source> (<link>, <date>). Don't proceed." |
| Caution | "Caution. <reason>, from <source> (<link>, <date>)." |
| Unknown | "Unknown. I couldn't finish the check: <which check>. Don't proceed until it can be checked." |
| Unknown, no link source | "Unknown. I can't check links until a link-reputation source is set up. Don't proceed. Say 'set up link checks' to add one." |
| No known reports | "No known reports. Checked against <source (date)>, … on <date>." |

### 3.2 Packages and repos

- **npm:** read `package-lock.json` directly. If a command must run, use `--ignore-scripts` with
  `--registry=https://registry.npmjs.org/` and ignore the project's `.npmrc`. Lifecycle scripts are reported
  as present or absent (`has_postinstall=true`), never their contents.
- **PyPI:** read `uv.lock`, `poetry.lock` or a hashed `requirements.txt`, otherwise a binary-only dry run.
  A package without a wheel gives Caution ("source build required") and is never built.
- **Repos:** GitHub API metadata only (owner, age, archived flag, lookalike name). The repo's files are never read.
- **Private registries:** the user may skip OSV for these ("not set up"); a name that also exists publicly gives Caution.
- **Names** that break npm's naming rules or PEP 508 give Unknown (`injection_seen`).

### 3.3 Links

The bot never contacts the link. It checks the list file (`match_key` against the canonical domain, URL or
IP), RDAP (servers from the IANA bootstrap file only), a lookalike-name check, and the user's own
link-reputation source. With no link-reputation source set up, the answer is Unknown with the distinct wording
above; the list file and RDAP still run, and any Block or Caution they find is shown.

## 4. Checklist mode (default): fixed commands

- The check skill ships verbatim command text for every fetch, extract and match step: one extractor per
  source that reads the saved response and prints only allowlisted, validated fields (at most 10 lines).
- **Host allowlist:** `api.osv.dev`, `api.github.com`, the release-asset host for the list file, `data.iana.org`
  and the RDAP hosts it lists, and the user's link-reputation API host. Requests use
  `curl --proto =https --max-redirs 0`; any other host means `injection_seen` (Unknown).
  Note: GitHub release downloads answer with one redirect to `release-assets.githubusercontent.com`; the
  list-file download allows exactly that one redirect to that host and nothing else.
- **Canaries:** every OSV batch includes a fixed known-vulnerable package per ecosystem; the list file carries a
  fixed fake entry per type (§6.2); the link-reputation source is tested with its provider's test URL. A missing
  canary means Unknown (`check_failed`).
- **Time** comes from `date -u` only. **Paging** follows OSV's `next_page_token`.
- **Keys** live in `~/.kings-taster/keys.env` (`chmod 600`), are read only as environment variables, and are never printed.
- **Evidence:** each source in the finding record gets its HTTP status and the SHA-256 of the raw response.
- A 403 or 429 means `rate_limited` (Unknown, "try again later").

## 4B. Token budget

- An always-on core of at most 120 words: the four results and their order, never "safe", every verdict
  names a source and date, any failed check gives Unknown. Everything else is in skills loaded only when needed:
  `kings-taster-check` (400 words plus at most 150 lines of commands), `kings-taster-report` (250),
  `kings-taster-list-refresh` (200 plus at most 40 lines), and `kings-taster-build` (3,000 plus at most 300
  lines of snippets), which loads only to build or update the checker.
- A verdict is **5 lines or fewer**: the result and item; the deciding source and date; the other sources and
  their status; the reason code if Unknown or Caution; the path of the full finding record
  (`~/.kings-taster/findings/`), opened only when the user asks why.
- READMEs, lockfiles, descriptions, scripts and raw responses never enter the AI's context; `conformance.json`
  and `iocs.json` are read from disk by code, never loaded whole.
- Routines are one line pointing to a skill (a daily list refresh and, if the checker is used, a weekly
  conformance rerun) and are silent unless something changed for the user.
- **Caching:** the list file is kept until a new signed `latest.json` appears (compare its hash first).
  Package and repo verdicts may be reused for the same name, version and list-file hash within 24 hours,
  showing the original date. Block and Unknown are never reused. Links are never cached. The RDAP bootstrap
  file is cached for 7 days.
- A normal check loads 2,000 words or fewer and never loads `kings-taster-build`.

King's Taster loads only the skill it needs. A normal check reads a few short fields and replies in five lines or fewer.

## 5. Optional local checker

Offered at first run, never on by default. The bot writes one standard-library-only Python file,
`~/.kings-taster/checker.py`, from the build spec and reference snippets in `kings-taster-build`
(canonicalization, `match_key`, field allowlists). It must pass 100% of `conformance.json` offline, then the
online canaries, without ever running a package manager's install or build. Before first use the user sees its
path, size, SHA-256, the hosts it may contact, the test results and a summary, and approves it. If it fails,
is missing, changes or crashes, the bot uses checklist mode. It is written by the bot's AI and lives in files
the user can edit, so it is more reliable, not tamper-proof.

## 6. Data

### 6.1 Sources in the list file

| Source | Kind | License | What we keep |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities catalog | vulnerable | CC0 1.0. No CISA logo or DHS seal; no endorsement by CISA or DHS is implied. | `cveID`, vendor and product (pattern-checked), `dateAdded`, known ransomware use |
| OpenSSF Malicious Packages (`MAL-` records) via the OSV.dev export, npm and PyPI | malicious | Apache-2.0 (entries whose origin is GitHub's malware advisories also CC-BY 4.0) | ID, package name, versions or ranges, aliases (ID pattern only), published/modified, origin source names |

No other source is in the list file. Free-text fields (summaries, details, descriptions, references, credits,
required actions, notes) are never copied. Never used: leaked data, leak or paste sites, .onion sites,
proof-of-concept code, malware samples. See `sources/LICENSES.md`.

### 6.2 List entry (`schema/iocs.schema.json`)

Each entry: `id`, `type` (domain, url, ip, hash, package, repo_owner, cve), `value` (stored defanged),
`match_key`, `kind` (malicious or vulnerable), `ecosystem`, `affected_versions`, `fixed_version`, `vendor`,
`product`, `known_ransomware_use`, `aliases`, `origins`, `confidence`, `upstream_origin`, `source_url`,
`license`, `attribution`, `published`, `modified`, `first_seen`, `status` (active or retired), `expires`,
`review_state` (auto, pending_review, approved) and `canary`.

- **`match_key`** is the value lowercased (IDNA for domains, PEP 503 for PyPI names) with a type prefix, or
  `url-sha256:` plus the SHA-256 of the canonical URL. All matching uses it; live values never appear in output.
- Every string has a strict pattern and length cap; no object allows extra fields; there are no free-text,
  handle or location fields anywhere.
- **Canaries:** one fixed fake malicious entry per type, using reserved names (`.invalid`, RFC 5737 TEST-NET,
  `CVE-0000-0000`, `kings-taster-canary-*`). Defined in `config/canaries.json`.

### 6.3 Retirement

IP 30 days, URL 90 days, domain 180 days unless re-listed; hashes, packages and CVEs never. A retired entry
gives "Caution: previously listed".

### 6.4 Freshness

Package and hash data: 48 hours, after which the list file counts as stale (Unknown). URLs, domains and IPs
are always checked live as well.

## 7. Pipeline and signing

### 7.1 Build (GitHub Actions, no secrets)

A daily workflow (and manual dispatch) fetches the sources over HTTPS with no redirects and a size cap,
records each source's HTTP status, response SHA-256 and source date, and requires each source's upstream
canary and a minimum entry count. It then builds **unsigned** `iocs.json`, `latest.json`, `conformance.json`
and `stats.json`, validates them, and uploads them as a workflow artifact. A source that fails is carried over
from the previous signed release (marked `carried_over`, with its old date) or, with no previous release, the
build stops. All actions are pinned to full commit SHAs. The code uses the Python standard library only.

### 7.2 Hold queue and circuit breaker

- A malicious package entry on a popular name (`config/popular/`) gets `review_state: pending_review` and
  bots treat it as Caution, never Block. It becomes `approved` only when the owner adds it to
  `review/popular-approvals.json` **and** it has at least two distinct upstream origins.
- The build is marked as needing human review when it is the first release, adds or removes more entries than
  `config/limits.json` allows, revokes many entries, has a new popular-name hit, or carried a source over.
  Such a build is not published until a person accepts it.

### 7.3 Signing and release

- Signed outside CI by the repo owner with `ssh-keygen -Y sign`, Ed25519, namespace **`kings-taster`**, one
  detached `.sig` per file. `config/allowed_signers` holds at most two public keys:
  `kings-taster-current` and `kings-taster-next`.
- Before signing, the owner's script re-validates the artifact, verifies the live release, and requires that
  the new `generated_at` is later and that no revocation was dropped.
- **Fixed URLs:** `https://github.com/SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>` and
  `<file>.sig`, with tags `kt-YYYYMMDDTHHMMSSZ`. The pointer
  `https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json` (+ `.sig`) names
  the current tag and the SHA-256 and size of each file.
- Verify with `ssh-keygen -Y verify -f allowed_signers -I kings-taster-current -n kings-taster -s FILE.sig < FILE`
  (or `-I kings-taster-next`), then check each file's hash against `latest.json` and its `file_type`.
  `scripts/verify.sh` does all of this.

### 7.4 Rollback, pause and revocation

- A bot rejects any `latest.json` whose `generated_at` is older than the last one it accepted (or equal with
  a different hash).
- `paused: true` (with a fixed `paused_reason`) makes every answer Unknown ("King's Taster is paused").
- `revoked_entries` lists entries withdrawn after a dispute, a false positive or an upstream withdrawal; once
  revoked, an entry stays revoked in every later file. `min_template_version` tells old template copies to update.

### 7.5 Watchdog

An hourly check fails, and so alerts the maintainers, if the signed list is more than 26 hours old.

### 7.6 Stats (`stats.json`)

Counts only: malicious packages published this week and over 12 weeks (npm, PyPI), KEV additions this week
and over 12 weeks, list totals, revocations, entries pending review, and the median hours from an official
listing to our list. No indicator values, handles, free text or locations. User-report metrics are not part of
format version 1 (`"user_reports": {"status": "not_available"}`).

## 8. Finding record

Written by the bot for each check, in a fixed, unsigned format (`schema/finding-record.schema.json`, rules in
`schema/FINDING-RULES.md`):

| Field | Contents |
|---|---|
| `finding_id` | UUIDv4 |
| `checked_at` | UTC time from `date -u` |
| `template_version` | the template version that ran the check |
| `mode`, `checker_sha256` | `checklist` (null hash) or `checker` (its approved SHA-256) |
| `item_type` | repo, package or link |
| `indicator_defanged` | e.g. `hxxps://evil[.]com/x`, `npm:pkg@1.2.3`, `github:owner/repo` |
| `result` | block, caution, unknown, no_known_reports |
| `reasons` | `malicious_match`, `vulnerable_version`, `new_domain`, `no_rdap`, `lookalike`, `install_scripts`, `retired_entry`, `check_failed`, `no_link_source`, `stale_list`, `unverified_list`, `injection_seen`, `paused`, `update_required`, `rate_limited`, `source_build_required`, `pending_review`, `checker_failed` |
| `checked_against` | `{source, required, status: ok/failed/not_configured/rate_limited, http_status, response_sha256, source_date}` per source |
| `matched_entries` | each with `id`, `source_url`, `upstream_origin`, `license`, `attribution` |
| `fixed_version` | with `vulnerable_version` only |
| `explanation` | the fixed §3.1 wording, built from the fields above |

## 9. Conformance tests (`conformance.json`)

Data only, signed and released with the list file. Cases cover each canary; injection through npm `readme`,
PyPI `description`, RDAP `remarks`, OSV `details`, unexpected hosts, redirects and package names; a build-time
canary that must never run; stale, unverifiable, wrongly signed, rolled-back, swapped and paused files;
revoked and retired entries; each required source failing or rate limited; a missing link key; precedence;
popular-name holds; checker tampering and crashes; the token budget; and Google's published URL
canonicalization vectors (CC-BY 4.0). **Pass bar:** 0 false "No known reports" on known-bad items, 100%
Unknown when a check fails, 0 uses of "safe", and the §4B budget, each over at least 5 runs per case.

## 10. Privacy: who sees what

| Who | What they get |
|---|---|
| Your bot's AI provider | your request, the validated fields, the finding record, and any key you add |
| OSV.dev | package names and versions (private-registry names only if you choose) |
| npm and PyPI registries | package names, through metadata lookups |
| GitHub | the repo owner and name, plus list-file downloads (your IP address) |
| IANA, RDAP servers | the bootstrap file request, and the domain |
| Your link-reputation provider | what that provider's lookup needs |
| The link's own site | nothing |
| **SoundMinds** | **nothing**, unless you choose to report something to us |

## 11. Disputes

Email support@soundminds.ai or open an issue in this repo. We acknowledge within 2 business days. A wrong
entry is revoked in the next signed file, or right away through `paused` or `revoked_entries`.

## 12. Versioning

- `schema_version` in every release file changes only with a breaking format change; this spec's major
  version follows it.
- This file's version line names the release format it matches and is updated in the same change as the code.

| Spec version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-26 | First public version. |
