# kings-taster-list-refresh

Load when the daily list-refresh routine runs, or when a check finds a stale list. Not on a normal check.

Never say "safe". Never print or summarize a key. Never read a raw list file or README. Never contact an item's URL, and never clone, install, or run anything. Write only under `~/.kings-taster/` and temp. Time comes only from `date -u`.

Compare the signed `latest.json` and manifest hashes with the cache before downloading anything. Keep the cached manifest and shards until a new signed manifest appears. Refetch a cached shard only if its SHA-256 in the new manifest changed. Do not download shards that are not already cached. Verify with the official verifier before using any new file.

Hosts: only `github.com` for `/SoundMindsAI/kings-taster-data/releases/download/…`, and `release-assets.githubusercontent.com` for the one allowed list-file redirect. Any other host is `injection_seen`. Package and hash data in the list is stale after 48 hours.

Stay silent when the refresh succeeds. If verify fails or the list cannot be updated, say so in 3 lines or fewer and do not use the new files; the last good cache stays in place.

Run the Commands exactly.

<!-- commands -->
## Commands

Hosts: `github.com` (only `/SoundMindsAI/kings-taster-data/releases/download/…`) and `release-assets.githubusercontent.com` (only the one list-file redirect). Any other host is `injection_seen`.

Time: `date -u +%Y-%m-%dT%H:%M:%SZ`. Fetch: `curl --proto =https --max-redirs 1 -sS -L -o "$RAW" -w '%{url_effective}\n'` for `https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json` and `latest.json.sig`. The effective host must be `github.com` or `release-assets.githubusercontent.com`. If `latest.json` changed, fetch `manifest.json`, `iocs.json`, `conformance.json`, `stats.json` and their `.sig` files the same way from the tagged release. Then fetch only already-cached shards whose SHA-256 in the new manifest changed, from that tagged URL, the same way. Never use `-L` except this list fetch. Do not contact an item's own URL.

Verify a new directory with `scripts/verify.sh DIR --allowed-signers allowed_signers --state ~/.kings-taster/verify-state.json --update-state` (or `python3 -E -s -m kt.verify`). That runs `ssh-keygen -Y verify -f allowed_signers -I kings-taster-current -n kings-taster -s FILE.sig < FILE` (or `-I kings-taster-next`), checks each file's SHA-256 and `file_type` against `latest.json` and each shard against `manifest.json`, enforces the 64 KiB signature cap, honors `keys.json` and `root_pins` (a missing `keys.json` is refused once the pins are published), writes a watermark after a successful verify, and uses `--state` to refuse rollback. On failure, keep the last good cache.

Cache under `~/.kings-taster/list/`.
<!-- /commands -->
