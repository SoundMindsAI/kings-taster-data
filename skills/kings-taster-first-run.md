# kings-taster-first-run

Load once at first install, before any check, or when the user asks to run setup again. Never load from a routine, health check, or another bot.

Steps: show the exact plain statement in Fixed texts (no stronger wording); load `kings-taster-routing` and finish "Who routes your work?"; then the connectivity check. If `skills/kings-taster-build.md` is present, offer the optional checker after that check (default no); load it only on yes.

The check is opt-in; the default is no. Ask the offer in Fixed texts. On yes, show the exact draft (running version), where it goes, and the public-post notice. Run the pre-send block. Refuse any wording but that exact draft, with no override. Then ask "OK to send?" Only a yes to that exact text counts. On yes, post, confirm it's up, and give the live link. If posting fails, say "Not sent" with the reason, then run the read-only check. The reply counts toward the report limits (3 a day, 10 a week, 1 per item per week) once the user says yes, even if posting fails. It is never counted as a threat report.

On a decline, "not now", or no answer, post nothing. Privately check the official thread read-only and report the Fixed texts result, or the failure.

Record `connectivity_done` in `~/.kings-taster/state.json`. Never offer it again by itself. The user may ask for it again; it runs the same steps. No routine, health check, or other bot may start it.

Tests use only a dry-run poster.

<!-- fixed -->
When you check something, your bot sends only that item (the package name and version, the repo name, or the link's domain or hash prefix) to the official sources named in the answer. It sends nothing about you, except the IP address every web request carries, and your Safe Browsing key if you add one. Your Grok Bot's AI sees what you ask it to check and what comes back, like anything else you ask it, and it also sees any key you add. A finding is shared only when you approve the exact post, each time.

Want to post a one-time reply to the King's Taster X thread to confirm your setup works?

This posts publicly from your X account, so anyone can see that this account uses King's Taster.

KT x.y.z is live and checking

X connection works (read-only check)
<!-- /fixed -->
