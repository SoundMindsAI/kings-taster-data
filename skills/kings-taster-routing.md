# kings-taster-routing

Load at first run, when asked to change routing, or as weekly health item 4. Not on a normal check.

Never edit another bot. The only text added to another bot is the line below (30 words or fewer).

Ask "Who routes your work?" and offer three choices:

1. "I have a chief-of-staff bot." Show the line. The user pastes it, or approves one message asking that bot to add the line, then approves the change where that bot asks.
2. "No chief of staff." List bots whose descriptions mention code, repos, packages, installs, downloads, browsing or links. The user ticks which to cover. Each gets the line by paste or an approved message.
3. "Just this bot." Say the just-this-bot line in Fixed texts. Set up nothing else.

Save the choice and covered bots' names only in `~/.kings-taster/routing.json`. Never save instructions, descriptions, or message text.

Weekly check (health item 4): for each covered bot, first method that works — read its instructions if you can; if messaging was approved at first run, ask it yes or no; otherwise ask the user. If those abilities are missing, the user pastes and the weekly check asks the user.

Silent when the line is in place. If missing, send one nudge that week (missing-line text plus the line). Never add the line back yourself. If a covered bot has not asked King's Taster in 30 days, add the 30-day note.

To change routing later, rerun this skill.

<!-- line -->
Before you or any bot downloads, installs or clicks anything new, ask King's Taster and wait for its verdict. Don't proceed on Block or Unknown.
<!-- /line -->

<!-- fixed -->
Ask me before you download, install or click something new.
The King's Taster line is missing from <bot>. Paste it again?
<bot> hasn't asked me anything in 30 days.
<!-- /fixed -->
