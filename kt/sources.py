"""Clearly licensed sources included in the list file, with license and attribution.

The public table is sources/LICENSES.md, with the same rows in sources/licensing.json.
Only sources with use=list_file in that table may be fetched by the pipeline.
"""

KEV = {
    "id": "cisa-kev",
    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "license": "CC0-1.0",
    "attribution": "CISA Known Exploited Vulnerabilities Catalog. No endorsement by CISA or DHS is implied",
    "source_url_base": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "upstream_origin": "cisa-kev",
}

OSV = {
    "npm": {
        "id": "osv-npm",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        "ecosystem": "npm",
    },
    "PyPI": {
        "id": "osv-pypi",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
        "ecosystem": "PyPI",
    },
}
OSV_MAL_LICENSE = "Apache-2.0"
OSV_MAL_ATTRIBUTION = "OpenSSF Malicious Packages via OSV.dev"
# MAL records whose origins include GitHub's malware advisories also carry GHSA content (CC-BY 4.0).
GHSA_ORIGIN = "ghsa-malware"
GHSA_LICENSE_SUFFIX = " AND CC-BY-4.0"
GHSA_ATTRIBUTION_SUFFIX = "; GitHub Advisory Database (CC-BY 4.0)"
OSV_SOURCE_URL = "https://osv.dev/vulnerability/"

KT_LIST = {
    "license": "MIT",
    "attribution": "King's Taster canary (SoundMinds)",
    "source_url": "https://github.com/SoundMindsAI/kings-taster-data/blob/main/config/canaries.json",
    "upstream_origin": "kings-taster-canary",
}

# Pipeline fetchers allowed by sources/licensing.json (tests check this list).
LIST_FETCHERS = ("cisa-kev", "osv-npm", "osv-pypi")
