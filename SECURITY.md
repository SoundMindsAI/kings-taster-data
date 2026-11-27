# Security policy

## Reporting a vulnerability

Please report security flaws privately, in either of these ways.

Through GitHub's private vulnerability reporting:

1. Go to this repo's **Security** tab.
2. Choose **Report a vulnerability** (or open
   <https://github.com/SoundMindsAI/kings-taster-data/security/advisories/new>).
3. Describe the flaw, how to reproduce it, and what it affects.

Or by email to support@soundminds.ai, with "Security" in the subject line. This works without a GitHub account.

Either way, the report isn't posted anywhere public. Please don't open a public issue or pull request for a
security flaw, and don't include real secrets or anyone's personal data in the report.

## What's in scope

- the pipeline in this repo (fetchers, build, validation, verification and signing scripts)
- the signed list files and their format (`iocs.json`, `latest.json`, `conformance.json`, `stats.json`)
- the specification in [SPEC.md](SPEC.md), including the checker build spec and the King's Taster template
  behavior it describes

Reports about the sources themselves belong with those projects: the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [OSV.dev](https://google.github.io/osv.dev/data/) and [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages).

## What to expect

We aim to reply within 3 business days, and to fix the flaw or pause the list (which makes every answer Unknown; see SPEC.md §7.4) within 30 days.
There is no bug bounty.

## Verifying our files

Once the first release is published, every release file except the shards has a detached OpenSSH signature (Ed25519, namespace `kings-taster`). Each shard's SHA-256 is listed in the signed `manifest.json`, so a changed shard is caught. The public keys are
in [config/allowed_signers](config/allowed_signers). The current signing key's fingerprint is:

```
kings-taster-current  SHA256:CKhwT695U0zdQ6CIgP3SCRoKfGDT7Gf0/YFEtB8BKp4 (ED25519)
```

A signed `keys.json` will name the current and next signing keys once the first one is published, and will be
verified against the master public keys in [config/root_pins](config/root_pins) (see SPEC.md §7.3A). Those
pins are not published yet. Master keys are held only by the maintainer, in two separate places, never by a
bot or the signing computer. A missing or unsigned `keys.json` is refused.

To verify a release, see "Verify a release" in the [README](README.md).

## Supported versions

| Part | Supported version |
|---|---|
| `SPEC.md` | 1.5 |
| List format (`schema_version`) | 1 |
