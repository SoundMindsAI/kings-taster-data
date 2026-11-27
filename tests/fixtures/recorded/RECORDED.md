# Recorded fixtures

Recorded once with live read-only GETs on Nov 26, 2026, 6:36 to 6:41pm ET (23:36 to 23:41 UTC),
`curl --proto =https --max-redirs 0`. Nothing was cloned.

| File | Source URL | HTTP | Response sha256 | Source date |
|---|---|---|---|---|
| `kev/known_exploited_vulnerabilities.trimmed.json` | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 200 | full response `a76360009e4a65794a2b8073df5475f7a787a3bb83c3bfad2b0c3434a067631a` (1,898,186 bytes, 1,805 entries) | catalogVersion 2026.11.25, dateReleased 2026-11-25T19:48:12Z, Last-Modified Wed, 25 Nov 2026 19:48:12 GMT |
| (not stored) npm `modified_id.csv` | https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv | 200 | `2393c0787f5b30b5017bcbff641ad19129795538d7254650e3c2f471232cb80b` (8,840,840 bytes; 233,173 records, 224,985 MAL-) | Last-Modified Thu, 26 Nov 2026 22:18:24 GMT |
| (not stored) PyPI `modified_id.csv` | https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv | 200 | `409aa99dada16aa94b953f3544b1b4b1a445daefcd24b249576cdfb51c450f98` (1,164,434 bytes; 27,090 records, 12,104 MAL-) | Last-Modified Thu, 26 Nov 2026 22:18:23 GMT |
| `osv/npm/MAL-2023-1238.json` (upstream canary), `MAL-2026-20668.json`, `MAL-2026-20672.json` | https://osv-vulnerabilities.storage.googleapis.com/npm/<id>.json | 200 each | stored as fetched except the `credits` field, which was removed (it held third-party contact details; the pipeline never copies it) | record `modified` |
| `osv/PyPI/MAL-2022-7440.json` (upstream canary), `MAL-2026-20650.json`, `MAL-2026-20653.json`, `PYSEC-2026-2946.json` (non-MAL control) | https://osv-vulnerabilities.storage.googleapis.com/PyPI/<id>.json | 200 each | as above: `credits` removed, everything else unchanged | record `modified` |

The KEV fixture is trimmed to 7 entries (chosen to cover the label edge cases: a leading ".", "è", a
narrow no-break space, an en dash, a ransomware "Known"); the top-level fields are unchanged.
The `all.zip` exports (npm 222,629,163 bytes) were **not** downloaded; tests build small zips from these records.
`MAL-*` records are Apache-2.0 (OpenSSF Malicious Packages); `PYSEC-2026-2946` is CC-BY 4.0 (PyPI Advisory Database).
