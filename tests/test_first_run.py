"""First-run routing and the opt-in connectivity reply (SPEC.md §4C, §4D, §10.1). No network."""
import json
import os
import re
import tempfile
import threading
import unittest

from kt import connectivity as CONN
from kt import firstrun as F
from kt import routing as R
from tests.helpers import REPO, load

INTERNAL = ("/workspace", "Boss", "Yak", "Copilot", "QA Lead")


def _limits():
    return load(os.path.join(REPO, "config", "limits.json"))


def _state(tmp):
    return os.path.join(tmp, "state.json")


class TestSkillTexts(unittest.TestCase):
    def test_routing_caps_and_line(self):
        body, line, fixed = R.split_skill()
        self.assertLessEqual(R.word_count(body), R.WORD_CAP)
        self.assertGreater(R.word_count(body), 120)
        self.assertEqual(line, R.LINE)
        self.assertLessEqual(len(line.split()), R.LINE_WORD_CAP)
        self.assertEqual(len(R.LINE.split()), 25)
        self.assertIn(R.ASK, body)
        self.assertIn(R.JUST_THIS_BOT, fixed)
        self.assertIn("The King's Taster line is missing from <bot>. Paste it again?", fixed)
        self.assertIn("<bot> hasn't asked me anything in 30 days.", fixed)
        self.assertIn("Never edit another bot", body)
        self.assertIn("~/.kings-taster/routing.json", body)
        self.assertIn("names only", body)

    def test_first_run_caps_and_fixed_texts(self):
        body, fixed = F.split_skill()
        self.assertLessEqual(F.word_count(body), F.WORD_CAP)
        self.assertGreater(F.word_count(body), 120)
        self.assertIn(F.PLAIN_STATEMENT, fixed)
        self.assertIn(CONN.OFFER, fixed)
        self.assertIn(CONN.APPROVAL_NOTICE, fixed)
        self.assertIn("KT x.y.z is live and checking", fixed)
        self.assertIn(CONN.READ_ONLY_OK, fixed)
        self.assertIn("opt-in", body)
        self.assertIn("default is no", body)
        self.assertIn("OK to send?", body)
        self.assertIn("no override", body)
        self.assertIn("never counted as a threat report", body)
        self.assertIn("3 a day, 10 a week, 1 per item per week", body)
        self.assertIn("connectivity_done", body)
        self.assertIn("kings-taster-routing", body)
        # Must not be triggerable as a routine.
        self.assertIn("Never load from a routine", body)

    def test_plain_statement_matches_readme_and_spec(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        with open(os.path.join(REPO, "SPEC.md"), encoding="utf-8") as f:
            spec = f.read()
        quote = re.search(r"\*\*The plain statement,\*\*[^\n]*\n\n> (.+)\n", spec).group(1)
        self.assertEqual(quote, F.PLAIN_STATEMENT)
        self.assertIn("\n" + quote + "\n", readme)
        self.assertIn(F.PLAIN_STATEMENT, F.split_skill()[1])

    def test_no_internal_paths_or_agent_names(self):
        for path in (R.SKILL_PATH, F.SKILL_PATH, os.path.join(REPO, "kt", "routing.py"),
                     os.path.join(REPO, "kt", "firstrun.py")):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for needle in INTERNAL:
                self.assertNotIn(needle, text, "%s in %s" % (needle, path))


class TestRoutingPaths(unittest.TestCase):
    def test_just_this_bot_sets_up_nothing_else(self):
        doc, actions, spoken = R.apply_choice("just_this_bot")
        self.assertEqual(doc, {"choice": "just_this_bot", "covered": []})
        self.assertEqual(actions, [])
        self.assertEqual(spoken, R.JUST_THIS_BOT)
        self.assertEqual(R.validate_routing(doc), [])

    def test_chief_of_staff_paste_or_approved_message(self):
        for delivery in R.DELIVERIES:
            doc, actions, spoken = R.apply_choice(
                "chief_of_staff", chief_name="Office lead", delivery=delivery)
            self.assertIsNone(spoken)
            self.assertEqual(doc["choice"], "chief_of_staff")
            self.assertEqual(doc["covered"], [
                {"name": "Office lead", "message_approved": delivery == "ask_to_add"}])
            self.assertEqual(actions, [{"bot": "Office lead", "method": delivery}])
            self.assertNotIn("edit", [a["method"] for a in actions])
            self.assertEqual(R.validate_routing(doc), [])

    def test_no_chief_covers_ticked_bots_only(self):
        bots = [
            {"name": "Mailer", "description": "reads email and never mentions the filter terms"},
            {"name": "Installer", "description": "Installs packages from npm and repos"},
            {"name": "Browser", "description": "Helps with browsing and links"},
            {"name": "Notes", "description": "meeting notes only"},
        ]
        listed = R.filter_candidates(bots)
        self.assertEqual(listed, ["Installer", "Browser"])
        self.assertNotIn("Mailer", listed)
        doc, actions, _ = R.apply_choice(
            "no_chief", ticked=["Installer"], delivery="paste")
        self.assertEqual([c["name"] for c in doc["covered"]], ["Installer"])
        self.assertEqual(actions, [{"bot": "Installer", "method": "paste"}])
        # Descriptions never land in routing.json.
        raw = json.dumps(doc)
        self.assertNotIn("Installs packages", raw)
        self.assertNotIn("description", raw)

    def test_routing_json_refuses_instructions(self):
        doc, _, _ = R.apply_choice("chief_of_staff", chief_name="Office lead")
        self.assertEqual(R.validate_routing(doc), [])
        bad = dict(doc)
        bad["instructions"] = "secret prompt text"
        self.assertTrue(any("forbidden" in e for e in R.validate_routing(bad)))
        covered = dict(doc["covered"][0])
        covered["description"] = "always-on instructions"
        bad2 = {"choice": "chief_of_staff", "covered": [covered]}
        self.assertTrue(any("forbidden" in e for e in R.validate_routing(bad2)))

    def test_save_and_load_round_trip(self):
        doc, _, _ = R.apply_choice("no_chief", ticked=["Installer", "Browser"], delivery="ask_to_add")
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "routing.json")
        R.save_routing(path, doc)
        self.assertEqual(R.load_routing(path), doc)
        saved = load(path)
        self.assertEqual(set(saved.keys()), {"choice", "covered"})
        self.assertEqual(set(saved["covered"][0].keys()), {"name", "message_approved"})

    def test_never_edits_another_bot(self):
        for choice, kw in (
            ("just_this_bot", {}),
            ("chief_of_staff", {"chief_name": "Office lead", "delivery": "ask_to_add"}),
            ("no_chief", {"ticked": ["Installer"], "delivery": "paste"}),
        ):
            _, actions, _ = R.apply_choice(choice, **kw)
            self.assertFalse(any(a["method"] in ("edit", "write_profile", "set_instructions") for a in actions))


class TestWeeklyCheck(unittest.TestCase):
    def test_silent_when_the_line_is_present(self):
        r = R.weekly_check("Installer", line_present=True, can_read=True)
        self.assertTrue(r["silent"])
        self.assertIsNone(r["nudge"])
        self.assertFalse(r["readd"])
        self.assertEqual(r["method"], "read")

    def test_one_nudge_when_the_line_is_missing(self):
        r = R.weekly_check("Installer", line_present=False, can_read=True)
        self.assertFalse(r["silent"])
        self.assertTrue(r["nudge"].startswith("The King's Taster line is missing from Installer. Paste it again?"))
        self.assertIn(R.LINE, r["nudge"])
        self.assertEqual(r["nudge"], R.nudge_text("Installer"))
        self.assertFalse(r["readd"])
        again = R.weekly_check("Installer", line_present=False, can_read=True,
                               already_nudged_this_week=True)
        self.assertIsNone(again["nudge"])
        self.assertFalse(again["silent"])

    def test_thirty_day_note(self):
        r = R.weekly_check("Installer", line_present=True, can_read=True, days_since_ask=30)
        self.assertFalse(r["silent"])
        self.assertEqual(r["note"], "Installer hasn't asked me anything in 30 days.")
        self.assertIsNone(r["nudge"])
        early = R.weekly_check("Installer", line_present=True, can_read=True, days_since_ask=29)
        self.assertTrue(early["silent"])
        self.assertIsNone(early["note"])

    def test_fallback_when_abilities_are_missing(self):
        r = R.weekly_check("Installer", line_present=True, can_read=False,
                           message_approved=False, can_message=False)
        self.assertEqual(r["method"], "ask_user")
        # Approved messaging still falls back if the bot cannot be reached.
        r = R.weekly_check("Installer", line_present=True, can_read=False,
                           message_approved=True, can_message=False)
        self.assertEqual(r["method"], "ask_user")
        r = R.weekly_check("Installer", line_present=True, can_read=False,
                           message_approved=True, can_message=True)
        self.assertEqual(r["method"], "ask_bot")


class TestFirstRunFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = _state(self.tmp)
        self.limits = _limits()

    def test_shows_plain_statement_then_routing_then_connectivity(self):
        poster = F.DryRunPoster()
        out = F.run("first_run", offer_answer="no", routing_choice="just_this_bot",
                    poster=poster, state_path=self.state, limits=self.limits)
        self.assertEqual(out["shown"]["plain_statement"], F.PLAIN_STATEMENT)
        self.assertEqual(out["shown"]["routing_ask"], R.ASK)
        self.assertEqual(out["routing"]["choice"], "just_this_bot")
        self.assertEqual(out["shown"]["routing"]["just_this_bot"], R.JUST_THIS_BOT)
        self.assertTrue(out["flow"]["offered"])
        self.assertFalse(out["flow"]["posted"])
        self.assertTrue(out["flow"]["read_only_check"])
        self.assertEqual(out["read_only"]["message"], CONN.READ_ONLY_OK)
        self.assertEqual(poster.posts, [])
        self.assertEqual(poster.reads, 1)
        self.assertTrue(load(self.state)[CONN.STATE_KEY])
        self.assertFalse(out["counts_as_threat_report"])
        self.assertFalse(out["counts_as_report"])

    def test_two_yeses_posts_exact_text_via_dry_run_only(self):
        poster = F.DryRunPoster()
        out = F.run("first_run", offer_answer="yes", send_answer="yes",
                    routing_choice="just_this_bot", running_version="1.4.0",
                    poster=poster, state_path=self.state, limits=self.limits)
        self.assertEqual(out["posted"], "KT 1.4.0 is live and checking")
        self.assertTrue(CONN.draft_allowed(out["posted"], "1.4.0"))
        self.assertEqual(poster.posts[0]["text"], "KT 1.4.0 is live and checking")
        self.assertTrue(out["live_link"].endswith("/reply"))
        self.assertTrue(out["counts_as_report"])
        self.assertFalse(out["counts_as_threat_report"])
        self.assertEqual(out["used"]["day"], 1)
        self.assertEqual(out["used"]["items"]["connectivity"], 1)
        self.assertEqual(out["shown"]["approval_notice"], CONN.APPROVAL_NOTICE)

    def test_send_decline_and_failed_post_are_read_only(self):
        poster = F.DryRunPoster()
        out = F.run("first_run", offer_answer="yes", send_answer="no",
                    poster=poster, state_path=self.state, limits=self.limits)
        self.assertIsNone(out["posted"])
        self.assertEqual(poster.posts, [])
        self.assertTrue(out["flow"]["read_only_check"])
        self.assertFalse(out["counts_as_report"])

        poster = F.DryRunPoster(post_ok=False)
        # Fresh state: a prior decline on this install already marks first-run done.
        failed_state = _state(self.tmp + "-failed")
        out = F.run("first_run", offer_answer="yes", send_answer="yes",
                    post_ok=False, poster=poster, state_path=failed_state, limits=self.limits)
        self.assertIsNone(out["posted"])
        self.assertTrue(out["not_sent"].startswith("Not sent:"))
        self.assertTrue(out["flow"]["read_only_check"])
        self.assertTrue(out["counts_as_report"])  # yes was given, even though the post failed

    def test_changed_draft_is_refused_with_no_override(self):
        self.assertFalse(CONN.draft_allowed("KT 1.4.0 is live and checking please", "1.4.0"))
        self.assertFalse(CONN.draft_allowed("Hello from King's Taster", "1.4.0"))
        self.assertTrue(CONN.draft_allowed("KT 1.4.0 is live and checking", "1.4.0"))

    def test_once_per_install_and_forbidden_triggers(self):
        poster = F.DryRunPoster()
        first = F.run("first_run", offer_answer="no", poster=poster,
                      state_path=self.state, limits=self.limits)
        self.assertTrue(first["flow"]["marks_done"])
        again = F.run("first_run", already_done=True, offer_answer="yes", send_answer="yes",
                      poster=poster, state_path=self.state, limits=self.limits)
        self.assertFalse(again["flow"]["offered"])
        self.assertIsNone(again["posted"])
        # The persisted flag is enough; the caller flag cannot clear it.
        again_default = F.run("first_run", offer_answer="yes", send_answer="yes",
                              poster=F.DryRunPoster(), state_path=self.state, limits=self.limits)
        self.assertFalse(again_default["flow"]["offered"])
        self.assertIsNone(again_default["posted"])
        # The user may ask later.
        later = F.run("user_request", already_done=True, offer_answer="yes", send_answer="yes",
                      poster=F.DryRunPoster(), limits=self.limits)
        self.assertEqual(later["posted"], "KT 1.0.0 is live and checking")
        for trigger in ("routine", "health_check", "bot_message"):
            out = F.run(trigger, offer_answer="yes", send_answer="yes",
                        poster=F.DryRunPoster(), limits=self.limits)
            self.assertFalse(out["flow"]["offered"], trigger)
            self.assertIsNone(out["posted"], trigger)

    def test_report_caps_block_a_third_daily_reply(self):
        poster = F.DryRunPoster()
        used = {"day": 3, "week": 3, "items": {"connectivity": 1}}
        out = F.run("first_run", offer_answer="yes", send_answer="yes",
                    poster=poster, used=used, limits=self.limits, state_path=self.state)
        self.assertIsNone(out["posted"])
        self.assertFalse(out["flow"]["draft_shown"])
        self.assertFalse(out["counts_as_report"])
        self.assertEqual(poster.posts, [])

    def test_no_poster_never_posts(self):
        out = F.run("first_run", offer_answer="yes", send_answer="yes",
                    poster=None, state_path=self.state, limits=self.limits)
        self.assertIsNone(out["posted"])
        self.assertTrue(out["not_sent"].startswith("Not sent:"))
        self.assertTrue(out["flow"]["read_only_check"])

    def test_setup_modules_have_no_live_poster(self):
        for mod in (F, CONN, R):
            with open(mod.__file__, encoding="utf-8") as fh:
                src = fh.read()
            self.assertNotIn("import tweepy", src, mod.__name__)
            self.assertNotIn("from tweepy", src, mod.__name__)
            self.assertNotIn("create_posts(", src, mod.__name__)
        self.assertTrue(hasattr(F, "DryRunPoster"))


class TestStateAndCapsFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = _state(self.tmp)
        self.limits = _limits()

    def test_second_first_run_reads_connectivity_done_from_state(self):
        poster = F.DryRunPoster()
        first = F.run("first_run", offer_answer="yes", send_answer="yes",
                      poster=poster, state_path=self.state, limits=self.limits,
                      running_version="1.2.3")
        self.assertEqual(first["posted"], "KT 1.2.3 is live and checking")
        self.assertTrue(load(self.state)[CONN.STATE_KEY])
        poster2 = F.DryRunPoster()
        again = F.run("first_run", offer_answer="yes", send_answer="yes",
                      poster=poster2, state_path=self.state, limits=self.limits,
                      running_version="1.2.3")
        self.assertIsNone(again["posted"])
        self.assertEqual(poster2.posts, [])
        self.assertFalse(again["flow"]["offered"])

    def test_already_done_flag_cannot_clear_persisted_done(self):
        F.run("first_run", offer_answer="no", poster=F.DryRunPoster(),
              state_path=self.state, limits=self.limits)
        poster = F.DryRunPoster()
        out = F.run("first_run", already_done=False, offer_answer="yes", send_answer="yes",
                    poster=poster, state_path=self.state, limits=self.limits)
        self.assertIsNone(out["posted"])
        self.assertEqual(poster.posts, [])
        self.assertFalse(out["flow"]["offered"])

    def test_used_is_persisted_in_state(self):
        poster = F.DryRunPoster()
        out = F.run("first_run", offer_answer="yes", send_answer="yes",
                    poster=poster, state_path=self.state, limits=self.limits)
        self.assertTrue(out["counts_as_report"])
        state = load(self.state)
        self.assertIn("day", state)
        self.assertGreaterEqual(state.get("day", 0), 1)
        self.assertGreaterEqual(state.get("items", {}).get("connectivity", 0), 1)
        # A new process that only sees the state file is still over the per-item cap.
        poster2 = F.DryRunPoster()
        again = F.run("user_request", offer_answer="yes", send_answer="yes",
                      poster=poster2, state_path=self.state, limits=self.limits)
        self.assertIsNone(again["posted"])
        self.assertEqual(poster2.posts, [])

    def test_limits_omitted_or_corrupt_does_not_post(self):
        used = {"day": 99, "week": 99, "items": {"connectivity": 99}}
        for bad in (None, {}, {"reports_per_install": {}}, "nope"):
            poster = F.DryRunPoster()
            out = F.run("first_run", offer_answer="yes", send_answer="yes",
                        poster=poster, used=dict(used), limits=bad, state_path=_state(self.tmp + "-x"))
            self.assertIsNone(out["posted"], bad)
            self.assertEqual(poster.posts, [], bad)

    def test_corrupt_state_is_refused_before_post(self):
        with open(self.state, "w") as f:
            f.write("{")
        poster = F.DryRunPoster()
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            F.run("first_run", offer_answer="yes", send_answer="yes",
                  poster=poster, state_path=self.state, limits=self.limits)
        self.assertEqual(poster.posts, [])

    def test_corrupt_usage_in_state_is_refused_before_post(self):
        with open(self.state, "w") as f:
            f.write('{"connectivity_done": false, "day": "plenty"}\n')
        poster = F.DryRunPoster()
        with self.assertRaises(ValueError):
            F.run("first_run", offer_answer="yes", send_answer="yes",
                  poster=poster, state_path=self.state, limits=self.limits)
        self.assertEqual(poster.posts, [])

    def test_concurrent_yeses_post_at_most_once_with_shared_used(self):
        used = {"day": 0, "week": 0, "items": {}}
        results = []

        def one():
            poster = F.DryRunPoster()
            out = F.run("first_run", offer_answer="yes", send_answer="yes",
                        poster=poster, used=used, limits=self.limits)
            results.append((out["posted"], len(poster.posts)))

        t1 = threading.Thread(target=one)
        t2 = threading.Thread(target=one)
        t1.start(); t2.start()
        t1.join(); t2.join()
        posts = sum(1 for posted, n in results if posted is not None)
        self.assertLessEqual(posts, 1, results)
        self.assertEqual(used["items"].get("connectivity"), 1)

    def test_concurrent_yeses_post_at_most_once_with_state_file(self):
        results = []

        def one():
            poster = F.DryRunPoster()
            out = F.run("first_run", offer_answer="yes", send_answer="yes",
                        poster=poster, state_path=self.state, limits=self.limits)
            results.append((out["posted"], len(poster.posts)))

        t1 = threading.Thread(target=one)
        t2 = threading.Thread(target=one)
        t1.start(); t2.start()
        t1.join(); t2.join()
        posts = sum(1 for posted, n in results if posted is not None)
        self.assertLessEqual(posts, 1, results)
        state = load(self.state)
        self.assertTrue(state[CONN.STATE_KEY])
        self.assertEqual(state["items"]["connectivity"], 1)

    def test_concurrent_yeses_with_separate_used_dicts_post_at_most_once(self):
        # Distinct used dicts must still share the module cap lock (and the
        # state file for the actual counts).
        results = []

        def one():
            poster = F.DryRunPoster()
            used = {"day": 0, "week": 0, "items": {}}
            out = F.run("first_run", offer_answer="yes", send_answer="yes",
                        poster=poster, used=used, state_path=self.state,
                        limits=self.limits)
            results.append((out["posted"], len(poster.posts)))

        t1 = threading.Thread(target=one)
        t2 = threading.Thread(target=one)
        t1.start(); t2.start()
        t1.join(); t2.join()
        posts = sum(1 for posted, n in results if posted is not None)
        self.assertLessEqual(posts, 1, results)
        state = load(self.state)
        self.assertEqual(state["items"]["connectivity"], 1)

    def test_symlinked_lock_path_is_refused(self):
        victim_dir = os.path.join(self.tmp, "outside")
        os.makedirs(victim_dir)
        victim = os.path.join(victim_dir, "victim")
        os.symlink(victim, self.state + ".lock")
        poster = F.DryRunPoster()
        with self.assertRaises(ValueError) as ctx:
            F.run("first_run", offer_answer="yes", send_answer="yes",
                  poster=poster, state_path=self.state, limits=self.limits)
        self.assertIn("symlink", str(ctx.exception).lower())
        self.assertEqual(poster.posts, [])
        self.assertFalse(os.path.exists(victim))


class TestVersionGate(unittest.TestCase):
    def test_fullwidth_and_malformed_versions_refused_before_post(self):
        poster = F.DryRunPoster()
        for v in ("", "1", "1.0", "v1.0.0", "1.0.0-rc1", "1.0.0\n", " 1.0.0",
                  "10.20.0.2", "9999.0.0", "１.０.０"):
            with self.assertRaises(ValueError):
                F.run("first_run", offer_answer="yes", send_answer="yes",
                      running_version=v, poster=poster, limits=_limits())
            self.assertEqual(poster.posts, [])
            with self.assertRaises(ValueError):
                CONN.draft(v)
            self.assertFalse(CONN.draft_allowed("KT %s is live and checking" % v, v) if v else False)

    def test_ascii_semver_is_accepted(self):
        self.assertTrue(CONN.draft_allowed("KT 2.3.4 is live and checking", "2.3.4"))
        self.assertFalse(CONN.draft_allowed("KT 2.3.4 is live and checking", "1.0.0"))

    def test_omitted_version_comes_from_the_package_not_a_hardcoded_default(self):
        import inspect
        import kt
        self.assertIsNone(inspect.signature(F.run).parameters["running_version"].default)
        poster = F.DryRunPoster()
        orig = kt.__version__
        try:
            kt.__version__ = "3.4.5"
            self.assertEqual(F.package_version(), "3.4.5")
            out = F.run("user_request", offer_answer="yes", send_answer="yes",
                        poster=poster, limits=_limits())
            self.assertEqual(out["posted"], "KT 3.4.5 is live and checking")
        finally:
            kt.__version__ = orig

    def test_missing_or_invalid_package_version_is_refused_before_post(self):
        import kt
        poster = F.DryRunPoster()
        orig = kt.__version__
        try:
            for v in (None, "", "1.0", "１.０.０"):
                kt.__version__ = v
                with self.assertRaises(ValueError):
                    F.run("first_run", offer_answer="yes", send_answer="yes",
                          poster=poster, limits=_limits())
                self.assertEqual(poster.posts, [])
        finally:
            kt.__version__ = orig
