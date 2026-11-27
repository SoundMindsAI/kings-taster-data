# King's Taster ("the King's Poison Taster"): public specification

**Spec version 1.7, matches kings-taster-data release format `schema_version: 1` (first signed release: not yet published).**
This document is versioned. It is updated in the same pull request as any change to the release files, the
schemas or the pipeline, and the version line above says which release it describes.

King's Taster checks things you're about to download, install or click (a GitHub repo before a clone or pull,
an npm or PyPI package before install, and a link before you open it) and answers with one of four results,
each citing its sources and their dates. It never says "safe".

---

## 1. Design rules

- **No SoundMinds server.** Each installed bot asks official sources directly and checks this repo's signed
  list file. Nothing is sent to SoundMinds unless you choose to report something to us.
- **Strict answers.** Never "safe" or "guaranteed". A clean answer is
  "No known reports. Checked against <source> (<date>), <source> (<date>) on <date>." Every verdict cites a source and a date. Any failed check means
  "Unknown, don't proceed".
- **Text-only template.** A Grok Bot template carries text (skills and routines as prose). Nothing runs at
  install. Checks are an AI following a fixed checklist with fixed commands, or an optional local checker the
  bot builds and the user approves (§5). The only deterministic code SoundMinds runs is this repo's pipeline,
  and it never receives user data.
- **Honesty line** (shown to users): King's Taster is an AI following a checklist against official sources.
  It can make mistakes or be tricked by what it reads. "No known reports" means nothing was found, not that
  it's safe. Your checks go from your bot to the sources listed, and to your bot's AI provider, never to
  SoundMinds. Any keys you add are visible to your bot's AI.
- The install button on [soundminds.ai/kings-taster](https://soundminds.ai/kings-taster) will be the only official place to get King's Taster from us. Don't install a copy from anywhere else.
- You will install King's Taster from [soundminds.ai/kings-taster](https://soundminds.ai/kings-taster) once that page is live.

## 2. Trust model

| Threat | Defense, and what's left |
|---|---|
| Prompt injection through a package name, a known-bad indicator (IOC) string, README, domain-registration (RDAP) field or API response | Fixed extraction commands print only allowlisted, validated fields (IDs checked by regex, ISO dates, fixed values, booleans, versions). No free-text field reaches the AI. Raw responses go to a temp file the AI never reads. Any instruction-like or pattern-breaking value means Unknown (`injection_seen`). **What's left:** an AI can still be fooled, and we say so. |
| A malicious project's own files (lockfile, `.npmrc`, build backend) | Binary-only resolution, `.npmrc` ignored, the default registry set on the command line, nothing ever built. |
| A phishing link tuned to read clean | A domain under 30 days old, or with no RDAP record, gives Caution. A link with no link-reputation source set up gives Unknown. |
| Mass false alarms on popular packages | `vulnerable` entries never Block. A malicious entry on a popular name is held at Caution (`pending_review`) until a person approves it, and approval also needs two distinct upstream origins (§7.2). |
| Poisoning the pipeline | The pipeline uses only deterministic parsers of structured feeds and never copies free text. A circuit breaker holds a build for human review when it adds, removes or withdraws too many entries at once, hits a popular package name, carries over a source from the previous release, or is the very first release (§7.2). |
| Stolen signing key, repo takeover, rollback | The private key never touches CI. Detached OpenSSH signatures; the current and next public keys are pinned; a signed `keys.json` will name those keys once it is published (§7.3A); `generated_at` must only move forward; `revoked_entries` only grows; fixed release-asset URLs; branch protection and CODEOWNERS. |
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
vulnerable (Caution, "upgrade to X or later"). A live malicious hit on a popular (top-10k) name is held at
**Caution: "reported malicious by OSV, pending review"** until the list file carries an approved entry.

| Answer | Fixed wording (the voice may change, the meaning may not) |
|---|---|
| Block | "Block. <item> is listed as malicious by <source> (<link>, <date>). Don't proceed." |
| Caution | "Caution. <reason>, from <source> (<link>, <date>)." |
| Unknown | "Unknown. I couldn't finish the check: <which check>. Don't proceed until it can be checked." |
| Unknown, no link source | "Unknown. I can't check links until a link-reputation source is set up. Don't proceed. Say 'set up link checks' to add one." |
| No known reports | "No known reports. Checked against <source> (<date>), <source> (<date>) on <date>." |

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

King's Taster loads only the skill it needs. A normal check reads a few short fields and replies in five lines or fewer.

- The always-on core is at most 120 words. It covers the four results and their order, never saying "safe",
  naming a source and date in every verdict, and giving Unknown for any failed check. Everything else is in
  skills loaded only when needed:
  `kings-taster-check` (400 words plus at most 150 lines of commands), `kings-taster-report` (250),
  `kings-taster-list-refresh` (200 plus at most 40 lines), `kings-taster-routing` (250 plus the 30-word line in
  §4C), `kings-taster-health` (250 plus at most 40 lines of fixed health commands, §4D), and `kings-taster-build` (3,000 plus at most 300 lines of snippets), which loads only to build or update
  the checker.
- A verdict is **5 lines or fewer**: the result and item; the deciding source and date; the other sources and
  their status; the reason code if Unknown or Caution; the path of the full finding record
  (`~/.kings-taster/findings/`), opened only when the user asks why.
- READMEs, lockfiles, descriptions, scripts and raw responses never enter the AI's context; `conformance.json`
  and `iocs.json` are read from disk by code, never loaded whole.
- There are two routines, each one line pointing to a skill: a daily list refresh, and one weekly health check
  (§4D). The weekly health check covers the conformance rerun and the routing check, so the self-check, the conformance rerun and the routing check share one weekly run instead of three separate ones. Both routines are silent unless something changed for the user.
- **Caching:** the list is sharded (§6.5), so the cache will be keyed on the manifest hash and each shard's SHA-256.
  The manifest and the cached shards will be kept until a new signed manifest appears. The bot will compare the signed
  `latest.json` and manifest hashes before downloading anything, and will refetch a cached shard only if its
  SHA-256 in the new manifest changed.
  Package and repo verdicts may be reused within 24 hours for the same name and version, with the same manifest
  hash and shard SHA-256, showing the original date. Block and Unknown are never reused. Links are never cached. The RDAP bootstrap
  file is cached for 7 days.
- A normal check loads 2,000 words or fewer and never loads `kings-taster-build`.

## 4C. First run: who routes your work

King's Taster works best when your other bots ask it before they download, install or click anything new.
King's Taster never edits another bot itself. It only helps you add one line to the bots you choose.

The line is the same everywhere and is never longer than 30 words:

> Before you or any bot downloads, installs or clicks anything new, ask King's Taster and wait for its verdict. Don't proceed on Block or Unknown.

At first run, King's Taster asks "Who routes your work?" and offers three choices:

1. **"I have a chief-of-staff bot."** King's Taster shows the line. You either paste it into that bot's
   instructions yourself, or approve King's Taster sending that bot one message asking it to add the line. You
   then approve that change wherever the other bot asks for it.
2. **"No chief of staff."** King's Taster lists your bots whose descriptions mention code, repos, packages,
   installs, downloads, browsing or links. You tick the ones to cover, and each one gets the line the same way,
   by your paste or by a message you approve.
3. **"Just this bot."** King's Taster says "Ask me before you download, install or click something new," and
   sets up nothing else.

King's Taster saves your answer and the names of the covered bots in `~/.kings-taster/routing.json`. That file
holds bot names only, never their instructions.

Once a week, the health check (§4D, item 4) confirms that the line is still there in each covered bot. It isn't
a separate routine. King's Taster reads the bot's instructions if it can see them. If you approved King's Taster
messaging that bot at first run, it asks the bot to answer yes or no. Otherwise, it asks you.

- The weekly check is silent when the line is in place.
- If the line is missing, King's Taster sends you one nudge that week, "The King's Taster line is missing from
  <bot>. Paste it again?", with the line included. It never adds the line back itself.
- If a covered bot hasn't asked King's Taster anything in 30 days, that week's message adds one note saying so:
  "<bot> hasn't asked me anything in 30 days." It's a fact, not an accusation.

Some bot setups don't let one bot list, read or message another. Where that's the case, you paste the line
yourself, and the weekly check asks you instead of the bot. The spec doesn't assume these abilities exist.

The `kings-taster-routing` skill loads only at first run, or when you ask to change the routing.
The 30-word line is the only text King's Taster adds to any other bot's always-on instructions.

Before release, all three first-run paths must pass tests. Those tests must confirm that King's Taster never changes another
bot without your paste or approval, that the line is 30 words or fewer, and that the weekly check stays silent
when the line is present and sends one nudge when it's removed.

## 4D. Health checks

**One weekly self-check.** A routine runs "Run kings-taster-health." It is silent when everything passes. It
checks four things:

1. **The list file:** it is fresh (under 48 hours old), its signature verifies, its version isn't older than the
   last one accepted, its date isn't more than 10 minutes ahead of `date -u`, and the manifest and every cached
   shard are under their size caps (§6.5). That 10-minute window is the client's check. Signing and the published
   verifier refuse a file dated more than 5 minutes ahead.
2. **Canaries:** for each required source, the fixed known-bad test item is caught. That means the OSV canary
   package, the list file's fake entry for each type, and Google's Safe Browsing test URL if it's set up. RDAP
   is tested with a fixed, known domain.
3. **The checker,** if it's in use: its SHA-256 still matches the approved one, and `conformance.json` passes 100%.
4. **The routing line** is still in each covered bot (§4C).

If item 1 or 2 fails, the bot tells you in at most 3 lines what failed, since when, and the one thing to do.
It writes `~/.kings-taster/health.json` with `status: failing`. While that is set, every check answers
"Unknown, don't proceed (health check failing: <reason>)". The next passing self-check or `status` run clears
it.

If item 3 fails, the bot tells you the same way, and it switches back to checklist mode instead of answering
Unknown. If checklist mode's own canaries pass, checks keep working.

If item 4 fails, you get the one weekly nudge from §4C. Verdicts aren't affected, because the checks still work
and only the routing has a gap.

**Status on demand.** You can say "King's Taster status" at any time. It runs all four items now and replies in
8 lines or fewer: one line per item, plus the list date and the mode (checklist or checker). It writes the same
`health.json`.

Before release, tests must break each item one at a time (a stale list, a bad signature, a future date, an
oversized file, a missing canary, a changed checker and a removed routing line). Each must be reported within
one self-check or `status` run, items 1 and 2 must turn every check into Unknown, a failing item 3 must switch
the bot to checklist mode, and a pass must clear it.

**First-run connectivity check.** This happens once, after the routing step (§4C).

1. King's Taster asks: "Want to post a one-time reply to the King's Taster X thread to confirm your setup
   works?" It is opt-in, and the default is no.
2. **On yes,** it shows the exact text, `KT x.y.z is live and checking` (with the running template version),
   and where it goes (the official thread's link). The approval prompt also says: "This posts publicly from
   your X account, so anyone can see that this account uses King's Taster." The draft then goes through the
   pre-send block (§10.1) and "OK to send?". On a yes, it posts and gives you the live link to the reply. If
   the post fails, it says "Not sent" with the reason, and runs step 3 instead.
3. **On a decline, "not now" or no answer,** it runs a read-only check: it reads the official thread
   post through the X connection's read tools and reports "X connection works (read-only check)" or the
   failure. Nothing is posted.
4. **Once per install.** It records `connectivity_done` in `~/.kings-taster/state.json` and never offers the
   check again by itself. No routine, health check or other bot can start it. You can ask for it again later,
   and that goes through the same steps.
5. The reply will count as one report toward the per-install report limits (3 a day, 10 a week, and 1 per item
   per week) as soon as the user says yes, even if posting then fails. It carries no finding data and is never
   counted as a threat report.

The fixed texts and test cases for these steps are in the `connectivity` section of `conformance.json`.

## 5. Optional local checker

King's Taster offers this checker at first run, and it is never on by default. The bot writes one standard-library-only Python file,
`~/.kings-taster/checker.py`, from the build spec and reference snippets in `kings-taster-build`
(canonicalization, `match_key`, field allowlists). It must pass 100% of `conformance.json` offline, then the
online canaries, without ever running a package manager's install or build. Before first use the user sees its
path, size, SHA-256, the hosts it may contact, the test results and a summary, and approves it. If it fails,
is missing, changes or crashes, the bot uses checklist mode. It is written by the bot's AI and lives in files
the user can edit. It is meant to be more consistent than checklist mode, but it is not tamper-proof.

## 6. Data

### 6.1 Sources in the list file

| Source | Kind | License | What we keep |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities catalog | vulnerable | CC0 1.0. No CISA logo or DHS seal; no endorsement by CISA or DHS is implied. | `cveID`, vendor and product (pattern-checked), `dateAdded`, known ransomware use |
| OpenSSF Malicious Packages (`MAL-` records) via the OSV.dev export, npm and PyPI | malicious | Apache-2.0 (entries whose origin is GitHub's malware advisories also CC-BY 4.0) | ID, package name, versions or ranges, aliases (ID pattern only), published/modified, origin source names |

No other source is in the list file. Free-text fields (summaries, details, descriptions, references, credits,
required actions, notes) are never copied. We never use leaked data, leak or paste sites, .onion sites, proof-of-concept code or malware samples. See `sources/LICENSES.md`.

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

An IP entry retires 30 days after its source last listed or updated it, a URL entry after 90 days and a domain
entry after 180 days. If the source lists or updates it again, the count starts over from that new date. Hash, package and CVE entries never
retire. A retired entry gives "Caution: previously listed".

### 6.4 Freshness

Package and hash data stays fresh for 48 hours, after which the list file counts as stale (Unknown). URLs, domains and IPs
are always checked live as well.

### 6.5 Sharding

A full build from a live fetch of the sources on 2026-11-26 was 196 MB, or 7.2 MB gzipped, with 238,538
entries, which is too much for a bot to download for every check. Those figures come from that live build, not
from the recorded test fixtures in this repo, which are a different snapshot. Each release therefore also splits
the list into shards. The full `iocs.json` stays in every release for the pipeline and for anyone who wants the
whole list, but a bot will download only the shard it needs.

- **Groups.** Each entry belongs to one group, read from the prefix of its `match_key`: `npm`, `pypi`, `kev`
  (CVE entries), `domain`, `url`, `ip`, `hash` or `repo_owner`.
- **Shard key.** `npm` and `pypi` are split by the first byte of the SHA-256 of the entry's `match_key` (written
  as two lowercase hex digits), giving 256 shards each. Every other group, including `kev`, is a single shard.
  The prefix length for each group is recorded in the manifest's `groups` field (`prefix_bytes`, 0 or 1).
- **Shard files.** `shard-<group>-<hex>.json` (for example `shard-npm-3f.json`), or `shard-<group>.json` for a
  single shard. Every shard is published, even an empty one, so a missing shard is always an error. A shard
  holds the full entries for its bucket, the `revoked_entries` whose `match_key` falls in it, and the same
  `generated_at` and `tag` as the rest of the release.
- **Signed manifest.** `manifest.json` lists every shard's name, file, group, bucket, SHA-256, size, gzipped size,
  entry count, revocation count and entry count per type, plus totals per group and per type. It is signed like
  the other release files, and `latest.json` gives its SHA-256 and size. Shards are not signed one by one. Instead,
  each shard's SHA-256 is listed in the signed manifest, so a changed shard is caught. That keeps a release under
  [GitHub's limit of 1,000 assets per release](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).
- **What the bot fetches.** The bot will verify `latest.json` and `manifest.json`, work out the one shard for the
  item from its `match_key`, download it, and check its SHA-256, size and entry counts against the manifest
  before using it. It will cache shards as described in §4B.
- **Caps.** The manifest is at most 5 MB, and each shard at most 5 MB gzipped (gzip level 9). The build and the
  validator refuse anything over a cap, and a client will reject it as `check_failed`. If a shard ever nears its
  cap, that group's prefix length will be raised. In a later live build that day (238,548 entries), the manifest
  was 122 KB, npm shards were 34 to 40 KB gzipped (802 to 958 entries each), PyPI shards were 2 to 4 KB
  gzipped, and the `kev` shard was 57 KB gzipped.
- **Privacy.** Fetching a shard never shows GitHub the item itself. For npm and PyPI, GitHub sees the item's group and a hash
  bucket shared by many items. For the other groups, which are not split, GitHub sees the whole group.

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
  `config/limits.json` allows, revokes many entries, has a new popular-name hit, or carries a source over.
  Such a build is not published until a person accepts it.

### 7.3 Signing and release

- The repo owner signs outside CI with `ssh-keygen -Y sign`, using Ed25519 and the namespace **`kings-taster`**, with one
  detached `.sig` per file for `latest.json`, `iocs.json`, `conformance.json`, `stats.json` and `manifest.json`.
  Shards are covered by their SHA-256 in the signed manifest (§6.5). `config/allowed_signers` holds at most two
  public keys: `kings-taster-current` and `kings-taster-next`.
- **Signature files.** A `.sig` file must be at most 64 KiB and hold exactly one OpenSSH signature. A larger file,
  or one with more than one signature, is refused before `ssh-keygen` runs.
- **Allowed-signers lines.** Each line is a principal (`kings-taster-current` or `kings-taster-next`), then a
  comma-separated option list, then an `ssh-ed25519` public key and an optional comment. The options may come in
  any order. `namespaces="kings-taster"` must appear exactly once; `valid-after="…"` and `valid-before="…"`
  (OpenSSH date forms) may each appear at most once; any other option, or a repeated one, makes the whole file
  invalid.
- Before signing, the owner's script re-validates the artifact, verifies the live release, and requires that
  the new `generated_at` is later and that no revocation was dropped.
- **Fixed URLs:** `https://github.com/SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>` and
  `<file>.sig`, with tags `kt-YYYYMMDDTHHMMSSZ`. The pointer
  `https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json` (+ `.sig`) names
  the current tag and the SHA-256 and size of each file.
- Verify with `ssh-keygen -Y verify -f allowed_signers -I kings-taster-current -n kings-taster -s FILE.sig < FILE`
  (or `-I kings-taster-next`), then check each file's hash against `latest.json` and its `file_type`, and each
  shard you use against `manifest.json`. `scripts/verify.sh` does all of this.

### 7.3A The keys file (`keys.json`)

The daily signing keys in `config/allowed_signers` will also be named in a signed `keys.json` once the first
keys.json is published. That file is not published yet.

- **What it holds.** `keys.json` lists the current signing key and, if there is one, the next key: each key's
  role, principal (`kings-taster-current` or `kings-taster-next`), algorithm (`ssh-ed25519`), public key,
  SHA-256 fingerprint, and validity window. A window is at most 90 days. Old keys are listed under
  `revoked_keys` with a fixed reason (`rotated`, `compromised` or `retired`). There are no free-text fields.
- **How it is signed.** A detached OpenSSH signature (`keys.json.sig`, Ed25519, namespace `kings-taster-keys`)
  covers the canonical JSON bytes of `keys.json` (the one standard, byte-for-byte form of the file). The signature must be made by one of the two master public
  keys, `kings-taster-root` or `kings-taster-root-backup`. `keys.json` must be 64 KiB or smaller (65,536 bytes). Those public keys will be published in
  `config/root_pins` and in SECURITY.md. Master keys are held only by the maintainer, in two separate places,
  never by a bot or the signing computer. The private signing key that signs the daily files never touches CI.
- **How a client will verify it.** The client pins both master public-key fingerprints. It checks the
  signature against those pins, that the file is canonical and matches the schema, that `generated_at` only
  moves forward and isn't more than 5 minutes ahead, and that a daily file was signed by a key that is listed,
  unexpired and not revoked (checked by that key's fingerprint, not only its name).
  Anything else is refused (the bot will treat the list as unverifiable and answer Unknown).
- **Until the first signed file is published.** `config/root_pins` holds no public keys yet. Daily files still
  verify against `config/allowed_signers` as in §7.3, so a release can still be verified without a `keys.json`.
  If a `keys.json` is present, it is refused until the master public-key pins are published. Once those pins
  are published, a release with no `keys.json` is refused (the bot will treat the list as unverifiable and
  answer Unknown).

### 7.4 Rollback, pause and revocation

- A bot rejects any `latest.json` whose `generated_at` is older than the last one it accepted (or equal with
  a different hash).
- `paused: true` (with a fixed `paused_reason`) makes every answer Unknown ("King's Taster is paused").
- `revoked_entries` lists entries withdrawn after a dispute, a false positive or an upstream withdrawal; once
  revoked, an entry stays revoked in every later file. `min_template_version` tells old template copies to update.

### 7.5 Watchdog and daily pipeline health check

An hourly watchdog fails, and so alerts SoundMinds, if the signed list is more than 26 hours old. Until
the first release exists, it passes with a notice. That hourly run also checks canaries and dates on the
pointer files it already downloads; it does not re-download every shard each hour.

A daily pipeline health check runs after each daily build, and again at sign-and-release before any files are
signed. It checks:

- **Build:** today's `latest.json`, `manifest.json` and every shard were built, with every shard's SHA-256
  matching the manifest.
- **Signing:** at sign-and-release, the health check runs on the unsigned files before any signing, and the
  canary entries must be present. If the check fails, a hold is not accepted, or anything else unexpected
  happens, nothing is signed and nothing is published. If health passes, or a person has accepted a hold,
  the files are signed and then verified against an allowed signing key. The unsigned CI build checks
  canaries and leaves signatures to sign-and-release.
- **No source went silent.** A source fails if its fetch failed, if it returned zero entries when it shouldn't,
  or if it added nothing for longer than its usual gap. The starting gaps are 3 days for OSV `MAL-` records and
  14 days for CISA KEV, recorded in `config/limits.json` under `pipeline_health`. They will be tuned from 30
  days of history.
- **Size caps:** the build already refuses a manifest over 5 MB or a shard over 5 MB gzipped (§6.5). The health
  check also holds for review a jump of more than 50% from one day to the next, in total size or in any shard.
- **Stale dates:** `generated_at` must be today's date (UTC) and not in the future when the daily build runs,
  and every entry's `first_seen` must be on or before `generated_at`. If there is no new release within 26
  hours, SoundMinds is alerted. After 48 hours with no release, clients answer Unknown for list matches on
  their own (§6.4).

On any failure there is no release that day. A size-jump hold also blocks publish until a person reviews and
reruns sign-and-release with `--accept-health`. The last good file stays live and keeps aging toward the
48-hour Unknown point, and SoundMinds is alerted.

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
canonicalization vectors (CC-BY 4.0). Cases for the pre-send block (§10.1) will cover drafts containing an IPv4
address, an IPv6 address, an email, each path form, the local username, the local hostname, an extra domain and
free text; each must be refused before "OK to send?", and a draft whose only IP or domain is the defanged
reported item must pass. Those cases are planned and are not in `conformance.json` yet. The `connectivity`
section holds the fixed texts and cases for the first-run connectivity reply (§4D): drafts the pre-send block
must allow or refuse, and one case per way the check can start or end. **Pass bar:** 0 false "No known reports" on known-bad items, 100%
Unknown when a check fails, 0 uses of "safe", and the §4B budget, each over at least 5 runs per case.

## 10. Privacy: who sees what

| Who | What they get |
|---|---|
| Your bot's AI provider | your request, the validated fields, the finding record, and any key you add |
| OSV.dev | package names and versions (private-registry names only if you choose) |
| npm and PyPI registries | package names, through metadata lookups |
| GitHub | the repo owner and name, plus downloads of `latest.json`, the manifest and the shard for each item (your IP address). A shard never shows the item itself: for npm and PyPI it shows the item's group and a hash bucket shared by many items, and for the other groups it shows the whole group (§6.5). |
| IANA, RDAP servers | the bootstrap file request, and the domain |
| Your link-reputation provider | what that provider's lookup needs |
| The link's own site | nothing |
| **SoundMinds** | nothing from lookups. The only finding data that leaves is a report you approve each time (§10.1). A "wrong verdict" GitHub issue is one you file yourself; King's Taster never files one. |

### 10.1 Data sharing rules

This section describes the King's Taster bot once it's available from the install page. These rules are a
release requirement.

**Lookups send only the item.** A check sends only the item to the official sources named in that check's
answer: the package name and version, the repo's owner and name, or the domain (or the link's 4-byte hash prefix
for Safe Browsing). Nothing about you is sent, with two exceptions. Like any web request, each lookup carries your bot computer's IP address. And a Safe Browsing key, if you add one, goes to Google with that lookup.
The daily list download goes to GitHub: `latest.json`, the manifest and the shards a check needs. A shard
never shows GitHub the item itself. For npm and PyPI, GitHub sees the item's group and a hash bucket shared by many items.
For the other groups, which are not split, GitHub sees the whole group (§6.5). Your IP address goes only to
the sources being queried, and to GitHub for the list downloads. It is never written into a report or any X post. Posting works the way any post on X
does: X sees the account that posts it.

**Reports are the only finding data that leaves.** The only other post King's Taster can make is the optional,
one-time connectivity reply (§4D). It carries no finding data and goes through the same steps below. Its only
allowed text is `KT x.y.z is live and checking`, where x.y.z is the running template version. The pre-send block
refuses any other text, including any added word, and there is no override. Every report goes through these steps:

1. **The pre-send block.** A report is built only from the fixed fields of the reply template: the marker line,
   the item type, the defanged item, the result, the source name and date, and one source link. A fixed
   scanner then checks the whole draft and refuses it if it finds anything beyond the reported item itself: an
   IPv4 or IPv6 address, an email address, a file path (`/…`, `~/…`, `C:\…`, `\\…`), a username (the output of
   `whoami` or `$USER`, any `@handle`, or a name from your bot list), a hostname (the output of `hostname`, or
   any domain other than the defanged item and the allowlisted source domains in the source link), or any free
   text outside the template fields. The reported item is exempt only as an exact match to its defanged form,
   so a malicious IP being reported can appear once, defanged. On a refusal, nothing is shown for approval. You
   see "Report blocked: it contained <type>", never the matched value, and the draft is deleted. There is no
   "send anyway"; you may start a fresh report, which is scanned again. In checker mode, `checker.py` runs the
   same scanner.
2. King's Taster shows the exact post text, character for character, and where it goes (the official thread's
   link).
3. It asks "OK to send?" every time. There is no standing approval, no batch approval and no "always allow".
   Only a yes to that exact text counts.
4. A decline is final for that finding. Any change to the text means showing it and asking again.
5. On a yes, King's Taster posts, reads the post back to confirm it's up, and gives you the live link to the
   reply. If the post fails, it says "Not sent" and shows the reason.

**The plain statement,** shown at first run, on the King's Taster page and in this repo's README:

> When you check something, your bot sends only that item (the package name and version, the repo name, or the link's domain or hash prefix) to the official sources named in the answer. It sends nothing about you, except the IP address every web request carries, and your Safe Browsing key if you add one. Your Grok Bot's AI sees what you ask it to check and what comes back, like anything else you ask it, and it also sees any key you add. A finding is shared only when you approve the exact post, each time.

No wording stronger than this statement is ever used.

## 11. Disputes

If you think a list entry is wrong, email support@soundminds.ai or open an issue in this repo. We acknowledge within 2 business days. A wrong
entry is revoked in the next signed file, or right away through `paused` or `revoked_entries`.

## 12. Versioning

- `schema_version` in every release file changes only with a breaking format change; this spec's major
  version follows it.
- This file's version line names the release format it matches and is updated in the same change as the code.

| Spec version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-26 | First public version. |
| 1.1 | 2026-11-26 | Adds §4C (first-run routing and the weekly routing check), the `kings-taster-routing` skill, and the install page. |
| 1.2 | 2026-11-26 | Adds §4D (the weekly health check and `status`), the `kings-taster-health` skill, the planned daily pipeline health check and size cap (§7.5), and the data sharing rules (§10.1). Folds the weekly routing check into the health check, so there are two routines. |
| 1.3 | 2026-11-26 | Adds the planned sharded list (§6.5): shards by ecosystem or type and hash prefix, a signed manifest, per-shard caching and caps, and what a shard download shows GitHub. Clarifies that a failing checker switches the bot to checklist mode rather than answering Unknown, and that the size caps are planned. |
| 1.4 | 2026-11-26 | Builds the sharded list (§6.5): `manifest.json` (signed) and 518 shards, npm and PyPI split by the first byte of SHA-256(`match_key`), one shard each for KEV and the other types, with 5 MB caps enforced by the build and validator. Adds the first-run connectivity check (§4D) and its pre-send rule (§10.1), with conformance cases. States the signature-file size limit and the allowed-signers option rules (§7.3). |
| 1.5 | 2026-11-27 | Adds §7.3A: the format and verifier for a signed `keys.json` that will name the current and next daily signing keys, with a 90-day validity window, `revoked_keys`, and signature namespace `kings-taster-keys`. The first signed `keys.json` and the master public-key pins are not published yet. Until they are, daily files still verify against `config/allowed_signers`, and a `keys.json` that is present is refused. A `keys.json` must be 64 KiB or smaller (65,536 bytes), and its `generated_at` may not be more than 5 minutes ahead. |
| 1.6 | 2026-11-27 | Once the master public-key pins are published, a release with no `keys.json` is refused (the bot will treat the list as unverifiable and answer Unknown). Until the pins are published, a release can still be verified without a `keys.json`, and a `keys.json` that is present is refused. |
| 1.7 | 2026-11-27 | Builds the daily pipeline health check (§7.5): after each daily build, and again at sign-and-release, it checks shard hashes, canaries, silent sources (starting gaps: 3 days for OSV `MAL-` records, 14 days for CISA KEV), date freshness, and a 50% size-jump hold. The hourly watchdog still alerts after 26 hours and also checks canaries and dates on the pointer files. |
