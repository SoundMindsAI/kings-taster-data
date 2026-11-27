# kings-taster-data
Signed public list of known-bad repos, packages and links, built only from official security sources, for the King's Taster Grok Bot by SoundMinds.

**King's Taster** ("the King's Poison Taster") checks a repo before a clone or pull, an npm or PyPI package
before install, and a link before you open it. It answers Block, Caution, Unknown ("don't proceed") or
"No known reports. Checked against <source> (<date>), <source> (<date>) on <date>." It never says "safe": "No known reports" means nothing
was found, not that something is safe.

King's Taster loads only the skill it needs. A normal check reads a few short fields and replies in five lines or fewer.

- **Specification:** [SPEC.md](SPEC.md) (versioned with the releases)
- **Sources and licenses:** [sources/LICENSES.md](sources/LICENSES.md)
- **Schemas:** [schema/](schema/) (list file, release pointer, shard manifest, stats, finding record)

## How to use it

**Coming soon.** You will install King's Taster from the install button on [soundminds.ai/kings-taster](https://soundminds.ai/kings-taster) once that page is live. That button will be the only official place to get it, so don't install King's Taster from anywhere else.

King's Taster is an AI, so it can be wrong or tricked. If it answers Unknown, or you have any doubt, don't proceed.

## What your bot sends

This describes the King's Taster bot once it's available from the install page.

When you check something, your bot sends only that item (the package name and version, the repo name, or the link's domain or hash prefix) to the official sources named in the answer. It sends nothing about you, except the IP address every web request carries, and your Safe Browsing key if you add one. Your Grok Bot's AI sees what you ask it to check and what comes back, like anything else you ask it, and it also sees any key you add. A finding is shared only when you approve the exact post, each time.

The bot will also offer, once, to post a public reply on X with fixed text and its version number, so you can see it's connected. It will ask first. Anyone can see that the account uses King's Taster, and the reply won't include what you checked or what King's Taster answered.

The full rules are in [SPEC.md §10.1](SPEC.md#101-data-sharing-rules).

## What's in a release

The first release hasn't been published yet. Until it is, the download links below won't work.

Every release is a GitHub release tagged `kt-YYYYMMDDTHHMMSSZ` with these files, each with a detached
OpenSSH signature (`.sig`, Ed25519, namespace `kings-taster`):

| File | What it is |
|---|---|
| `iocs.json` | the full list file: entries from the sources below, canaries, `revoked_entries`, `paused`, `min_template_version` |
| `manifest.json` | the shard manifest: each shard's file, SHA-256, size, gzipped size and entry counts |
| `latest.json` | the pointer: tag, `generated_at`, and the SHA-256 and size of each file. Also published at the fixed tag `kt-latest`. |
| `conformance.json` | test cases (data only) for checkers and checklist runs |
| `stats.json` | counts only, for the public page |

Each release also holds the list split into shards, 518 of them for now (`shard-npm-00.json` to `shard-npm-ff.json`, the same for
`pypi`, and one shard each for `kev`, `domain`, `url`, `ip`, `hash` and `repo_owner`). npm and PyPI entries go to
the shard named by the first byte of the SHA-256 of their `match_key`. Shards have no `.sig` of their own. Instead,
each shard's SHA-256 is listed in the signed `manifest.json`, so a changed shard is caught. A bot will download
only the shard it needs. That never shows GitHub the item itself. For npm and PyPI, GitHub sees the item's group
and a hash bucket shared by many items. For the other groups, which are not split, GitHub sees the whole group.
See [SPEC.md §6.5](SPEC.md#65-sharding).

Fixed download URLs:
`https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json` and
`https://github.com/SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>` (plus `.sig`).

## Verify a release

```sh
ssh-keygen -Y verify -f config/allowed_signers -I kings-taster-current -n kings-taster \
  -s latest.json.sig < latest.json
# or, for all five signed files plus hashes, file types, rollback, pause, freshness and any shards in the folder:
scripts/verify.sh <download-dir> --allowed-signers config/allowed_signers --state ~/.kings-taster/state.json --update-state
```

`config/allowed_signers` holds the current and next public keys. Reject any `latest.json` older than the last
one you accepted. A signed `keys.json` will name those same keys once the first keys.json is published, and will be
verified against the master public keys in `config/root_pins` (see [SPEC.md §7.3A](SPEC.md#73a-the-keys-file-keysjson)).
Those pins are not published yet. Until they are, a release is still verified against `config/allowed_signers`. If a `keys.json` is present before the pins are published, it is refused. Once the pins are published, a release with no `keys.json` is refused.

## How it's built

- `.github/workflows/pipeline.yml` (daily, and on demand) fetches CISA KEV and the OSV.dev export of OpenSSF
  malicious-package (`MAL-`) records for npm and PyPI over HTTPS, records each source's HTTP status, response
  SHA-256 and date, then builds and validates the **unsigned** files and shards, and uploads them as a workflow
  artifact. The build refuses a manifest over 5 MB or a shard over 5 MB gzipped. A pipeline health check then
  confirms that every shard matches its hash in the manifest, that the fixed known-bad test entries (canaries)
  are still caught, that no source has gone quiet, and that the dates are current. If any check fails, the job
  fails. If the list, or any one shard, grows by more than 50% from one day to the next, the release is held
  until a person reviews it. CI holds no signing key and no secrets.
- The owner signs and publishes with `scripts/sign-and-release.sh`, which re-validates the artifact, checks it
  against the live release (newer `generated_at`, no dropped revocations), stops on the circuit breaker, signs
  with `ssh-keygen -Y sign`, runs the same health check on the signed files, and creates the release.
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

## Contributing

If you think a verdict or a list entry is wrong, open an issue or email support@soundminds.ai. We don't accept pull requests from anyone outside SoundMinds, and any we receive are closed automatically. If you've found a security flaw, don't open an issue: report it privately as described in [SECURITY.md](SECURITY.md). The full rules are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Data notice

The MIT license in [LICENSE](LICENSE) covers our code and the data format only. Each list entry stays under
its source's own terms and carries its own `license`, `attribution`, `upstream_origin` and `source_url`:

- **CISA Known Exploited Vulnerabilities catalog:** CC0 1.0. Use of the data does not imply endorsement by
  CISA or DHS, and no CISA logo or DHS seal is used.
  Terms: <https://github.com/cisagov/kev-data/blob/develop/LICENSE> ·
  Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- **OpenSSF Malicious Packages (`MAL-` records, via OSV.dev):** Apache-2.0; a copy of the license will ship with
  every release as `Apache-2.0.txt`. Entries whose origin is GitHub's malware advisories also carry
  CC-BY 4.0 attribution to the GitHub Advisory Database.
  Terms: <https://github.com/ossf/malicious-packages/blob/main/LICENSE> ·
  OSV data sources: <https://google.github.io/osv.dev/data/> ·
  GitHub Advisory Database: <https://github.com/github/advisory-database>
- **Conformance test vectors** for URL canonicalization are from Google's Safe Browsing API documentation
  (CC-BY 4.0): <https://developers.google.com/safe-browsing/v4/urls-hashing>
