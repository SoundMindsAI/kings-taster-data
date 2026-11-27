# Sources and licenses (kings-taster-data v1)

Checked on Nov 26, 2026 against each source's own published terms.
Only the sources marked **included** feed the public list file. Everything else is a **pending** row and
is not fetched, parsed or republished until its row is cleared.

| Source | Status | License | Commercial use | Redistribution | Attribution we show | Key | Rate limit | Terms | What we keep |
|---|---|---|---|---|---|---|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) catalog, `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | **included** | CC0 1.0 | yes | yes | "CISA Known Exploited Vulnerabilities Catalog. No endorsement by CISA or DHS is implied." No CISA logo or DHS seal anywhere. | none | none published | [cisagov/kev-data LICENSE](https://github.com/cisagov/kev-data/blob/develop/LICENSE): "The KEV database is distributed under the Creative Commons 0 1.0 License … Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS." Third-party links inside KEV keep their own terms (we don't copy them). | `cveID`, `vendorProject`, `product` (pattern-checked), `dateAdded`, `knownRansomwareCampaignUse`. Never `vulnerabilityName`, `shortDescription`, `requiredAction`, `notes`. |
| OpenSSF Malicious Packages (`MAL-` records) via the OSV.dev GCS export, `https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip` | **included** | Apache-2.0 | yes | yes, with a copy of the license (to ship as `Apache-2.0.txt` in every release) | "OpenSSF Malicious Packages via OSV.dev" | none | none published for the bucket | [ossf/malicious-packages LICENSE](https://github.com/ossf/malicious-packages/blob/main/LICENSE) (Apache-2.0, no NOTICE file); [OSV data sources](https://google.github.io/osv.dev/data/) lists "OpenSSF Malicious Packages (Apache 2.0)" | `id`, package name, versions/ranges, `aliases` (ID pattern only), `published`, `modified`, origin source names. Never `summary`, `details`, `references`, `credits`. |
| GitHub Advisory Database content inside `MAL-` records whose origin is `ghsa-malware` | **included (as part of the row above)** | CC-BY 4.0 | yes | yes, with attribution | adds "; GitHub Advisory Database (CC-BY 4.0)" and license `Apache-2.0 AND CC-BY-4.0` on those entries | none | n/a | [github/advisory-database](https://github.com/github/advisory-database) README (CC-BY 4.0) | same fields as above; GHSA IDs kept only as aliases |
| Google Safe Browsing canonicalization test vectors (in `conformance.json`) | **included (test data only)** | CC-BY 4.0 (Google Developers docs) | yes | yes, with attribution | "Google Safe Browsing API documentation" | none | n/a | [URLs and hashing](https://developers.google.com/safe-browsing/v4/urls-hashing), [site policies](https://developers.google.com/site-policies) | the 33 published input/expected pairs, verbatim |
| OSV.dev non-MAL records (GHSA, PYSEC, etc.) | pending | varies per upstream (CC-BY 4.0, CC-BY-SA 4.0, CC-BY-NC-ND …) | varies | varies | n/a | none | n/a | [OSV data sources](https://google.github.io/osv.dev/data/) | not in the list file; bots query OSV live |
| Google Safe Browsing | **never in the list file** | Google APIs terms | — | **no** | — | — | — | [Safe Browsing terms](https://developers.google.com/safe-browsing/terms) | nothing |
| SafeDep | **pending** (license not cleared) | — | — | — | — | — | — | — | nothing |
| StepSecurity | **pending** (license not cleared) | — | — | — | — | — | — | — | nothing |
| Socket | **pending** (license not cleared) | — | — | — | — | — | — | — | nothing |
| NVD | pending | — | — | — | — | — | — | — | nothing |

**Our own code and data format:** MIT (see `LICENSE`). Each list entry stays under its source's terms and
carries its own `license`, `attribution`, `upstream_origin` and `source_url`.

Other services the template may contact live (npm and PyPI registries, GitHub REST API, RDAP/IANA) don't feed
the list file and aren't covered by this table.
