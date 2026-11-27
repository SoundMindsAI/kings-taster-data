# Security policy

## Reporting a vulnerability

Please report security flaws privately through GitHub's private vulnerability reporting:

1. Go to this repo's **Security** tab.
2. Choose **Report a vulnerability** (or open
   <https://github.com/SoundMindsAI/kings-taster-data/security/advisories/new>).
3. Describe the flaw, how to reproduce it, and what it affects.

Only you and the repo maintainers can see the report. Please don't open a public issue or pull request for a
security flaw, and don't include real secrets or anyone's personal data in the report.

## What's in scope

- the pipeline in this repo (fetchers, build, validation, verification and signing scripts)
- the signed list files and their format (`iocs.json`, `latest.json`, `conformance.json`, `stats.json`)
- the specification in [SPEC.md](SPEC.md), including the checker build spec and the King's Taster template
  behavior it describes

Reports about the sources themselves (CISA KEV, OSV.dev, OpenSSF Malicious Packages) belong with those projects.

## What to expect

We aim to reply within 3 business days, and to fix the flaw or pause the list (SPEC.md §7.4) within 30 days.
There is no bug bounty.

## Verifying our files

Every release file has a detached OpenSSH signature (Ed25519, namespace `kings-taster`). The public keys are
in [config/allowed_signers](config/allowed_signers). The current signing key's fingerprint is:

```
kings-taster-current  SHA256:CKhwT695U0zdQ6CIgP3SCRoKfGDT7Gf0/YFEtB8BKp4 (ED25519)
```

To verify a release, see "Verify a release" in the [README](README.md).

## Supported versions

| Thing | Supported |
|---|---|
| `SPEC.md` | 1.3 |
| List format (`schema_version`) | 1 |
