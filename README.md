# kings-taster-data
Signed public list of known-bad repos, packages and links, built only from official security sources, for the King's Taster Grok Bot by SoundMinds.

**King's Taster** ("the King's Poison Taster") checks a repo before a clone or pull, an npm or PyPI package
before install, and a link before you open it. It answers Block, Caution, Unknown ("don't proceed") or
"No known reports, checked against <sources> on <date>". It never says "safe": "No known reports" means nothing
was found, not that something is safe.

King's Taster loads only the skill it needs. A normal check reads a few short fields and replies in five lines or fewer.

- **Specification:** [SPEC.md](SPEC.md) (versioned with the releases)
- **Sources and licenses:** [sources/LICENSES.md](sources/LICENSES.md)
- **Schemas:** [schema/](schema/) (list file, release pointer, stats, finding record)

## What's in a release

The first release will be published right after this pipeline is merged. Until then, the download links below won't work yet.

Every release is a GitHub release tagged `kt-YYYYMMDDTHHMMSSZ` with these files, each with a detached
OpenSSH signature (`.sig`, Ed25519, namespace `kings-taster`):

| File | What it is |
|---|---|
| `iocs.json` | the list file: entries from the sources below, canaries, `revoked_entries`, `paused`, `min_template_version` |
| `latest.json` | the pointer: tag, `generated_at`, and the SHA-256 and size of each file. Also published at the fixed tag `kt-latest`. |
| `conformance.json` | test cases (data only) for checkers and checklist runs |
| `stats.json` | counts only, for the public page |

Fixed download URLs:
`https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json` and
`https://github.com/SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>` (plus `.sig`).

## Verify a release

```sh
ssh-keygen -Y verify -f config/allowed_signers -I kings-taster-current -n kings-taster \
  -s latest.json.sig < latest.json
# or, for all four files plus hashes, file types, rollback, pause and freshness:
scripts/verify.sh <download-dir> --allowed-signers config/allowed_signers --state ~/.kings-taster/state.json --update-state
```

`config/allowed_signers` holds the current and next public keys. Reject any `latest.json` older than the last
one you accepted.

## How it's built

- `.github/workflows/pipeline.yml` (daily, and on demand) fetches CISA KEV and the OSV.dev export of OpenSSF
  malicious-package (`MAL-`) records for npm and PyPI over HTTPS, records each source's HTTP status, response
  SHA-256 and date, then builds and validates the **unsigned** files and uploads them as a workflow artifact.
  CI holds no signing key and no secrets.
- The owner signs and publishes with `scripts/sign-and-release.sh`, which re-validates the artifact, checks it
  against the live release (newer `generated_at`, no dropped revocations), stops on the circuit breaker, signs
  with `ssh-keygen -Y sign` and creates the release.
- Malicious entries on popular package names are held at Caution (`pending_review`) until the owner approves
  them in `review/popular-approvals.json`, and approval also needs two distinct upstream origins.
- Python standard library only; no third-party packages. All GitHub Actions are pinned to full commit SHAs.

## Development

```sh
python3 -m unittest discover -s tests -t .        # offline, recorded fixtures
python3 scripts/secret_scan.py .                   # also runs in CI
scripts/install-hooks.sh                           # pre-push secret scan
```

## Disputes

If you think a list entry is wrong, email support@soundminds.ai or open an issue. We acknowledge within 2 business days.

## Data notice

The MIT license in [LICENSE](LICENSE) covers our code and the data format only. Each list entry stays under
its source's own terms and carries its own `license`, `attribution`, `upstream_origin` and `source_url`:

- **CISA Known Exploited Vulnerabilities catalog:** CC0 1.0. Use of the data does not imply endorsement by
  CISA or DHS, and no CISA logo or DHS seal is used.
  Terms: <https://github.com/cisagov/kev-data/blob/develop/LICENSE> ·
  Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- **OpenSSF Malicious Packages (`MAL-` records, via OSV.dev):** Apache-2.0; a copy of the license ships with
  every release as `Apache-2.0.txt`. Entries whose origin is GitHub's malware advisories also carry
  CC-BY 4.0 attribution to the GitHub Advisory Database.
  Terms: <https://github.com/ossf/malicious-packages/blob/main/LICENSE> ·
  OSV data sources: <https://google.github.io/osv.dev/data/> ·
  GitHub Advisory Database: <https://github.com/github/advisory-database>
- **Conformance test vectors** for URL canonicalization are from Google's Safe Browsing API documentation
  (CC-BY 4.0): <https://developers.google.com/safe-browsing/v4/urls-hashing>
