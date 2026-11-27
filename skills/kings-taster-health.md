# kings-taster-health

Load when the weekly health routine runs, or when the user says "King's Taster status" or "status". Never start the connectivity check from here.

Never say "safe". Never print or summarize a key. Never read a raw list file or README. Time comes only from `date -u`. Write `~/.kings-taster/health.json`.

The weekly run is silent when all four items pass. A `status` run replies in 8 lines or fewer: one line per item, the list date, and the mode (checklist or checker).

Items: (1) the list is fresh (under 48 hours), verifies, is not older than the last accepted file, is not more than 10 minutes ahead of `date -u`, and stays under the 5 MB caps; (2) required canaries are caught (OSV, the list's fake entries, Safe Browsing if set up, and RDAP on a fixed domain); (3) if a checker is in use, its SHA-256 matches and `conformance.json` passes 100%; (4) the routing line is still in each covered bot.

If item 1 or 2 fails, say in at most 3 lines what failed, since when, and what to do, and set `health.json` to `status: failing`. While that is set, every check answers "Unknown, don't proceed (health check failing: <reason>)". The next passing run or `status` clears it.

If item 3 fails, say so the same way and switch to checklist mode, not Unknown. If item 4 fails, send the one weekly nudge (missing-line text plus the line). Never add the line back. Verdicts are unchanged.

<!-- commands -->
## Commands

Time: `date -u +%Y-%m-%dT%H:%M:%SZ`. The client's future-date window is 10 minutes. List freshness is 48 hours. Caps: manifest 5 MB, each cached shard 5 MB gzipped.

Verify the cached list with `scripts/verify.sh DIR --allowed-signers allowed_signers --state ~/.kings-taster/verify-state.json` (or `python3 -E -s -m kt.verify`). That runs `ssh-keygen -Y verify -f allowed_signers -I kings-taster-current -n kings-taster -s FILE.sig < FILE` (or `-I kings-taster-next`), checks SHA-256 and `file_type` against `latest.json` and each cached shard against `manifest.json`, honors `keys.json` and `root_pins`, and uses `--state` to refuse a version older than the last accepted file. A failed verify is item 1 failing. Do not pass `--update-state` here unless a list-refresh already did; this run must not advance the watermark on a rollback.

Canaries: confirm the list's fake entry for each type; query the OSV canary package the same way as the check skill; if Safe Browsing is set up, include Google's test URL; test RDAP with a fixed known domain. A missing or uncaught required canary is item 2 failing. An unset Safe Browsing source is not a failure.

Checker: if a checker is in use, compare its SHA-256 to the approved value and run `conformance.json` (100% required). Routing: for each name in `~/.kings-taster/routing.json`, check the line is present. If it is missing, one nudge that week: "The King's Taster line is missing from <bot>. Paste it again?" plus the line. If a covered bot has not asked in 30 days, add "<bot> hasn't asked me anything in 30 days." Never edit another bot.

Write `~/.kings-taster/health.json` with `status` (`ok` or `failing`), `reason`, the list date, and the mode.
<!-- /commands -->
