"""Tests for the password strength estimator."""

import unittest

from securevault import strength


class ScoringTests(unittest.TestCase):

    def test_empty_password_scores_zero(self):
        result = strength.analyse("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["length"], 0)

    def test_obvious_password_is_weak(self):
        result = strength.analyse("password123")
        self.assertLess(result["score"], 20)
        self.assertTrue(strength.matches_common_password("password123"))

    def test_long_random_password_is_strong(self):
        result = strength.analyse("kR7#mQ2!xL9$vT4&zB8@p")
        self.assertGreaterEqual(result["score"], 75)

    def test_length_helps(self):
        short = strength.analyse("xK9#mQ2!")
        long = strength.analyse("xK9#mQ2!pT4&vB8@zL2$")
        self.assertGreater(long["score"], short["score"])

    def test_score_is_in_range(self):
        for password in ["a", "abc", "a" * 200, "!@#$%^&*()", "Correct-Horse-9"]:
            result = strength.analyse(password)
            self.assertGreaterEqual(result["score"], 0)
            self.assertLessEqual(result["score"], 100)

    def test_grade_letters(self):
        self.assertEqual(strength.grade_for_score(95)[0], "A")
        self.assertEqual(strength.grade_for_score(80)[0], "B")
        self.assertEqual(strength.grade_for_score(60)[0], "C")
        self.assertEqual(strength.grade_for_score(40)[0], "D")
        self.assertEqual(strength.grade_for_score(10)[0], "F")


class PatternTests(unittest.TestCase):

    def test_keyboard_sequences_are_caught(self):
        self.assertTrue(strength.contains_sequence("qwertyui"))
        self.assertTrue(strength.contains_sequence("asdfgh"))
        self.assertTrue(strength.contains_sequence("123456"))
        self.assertTrue(strength.contains_sequence("abcdef"))
        self.assertFalse(strength.contains_sequence("kR7#mQ2!"))

    def test_repeated_characters(self):
        self.assertEqual(strength.longest_repeat_run("aaabc"), 3)
        self.assertEqual(strength.longest_repeat_run("abc"), 1)
        self.assertEqual(strength.longest_repeat_run(""), 0)

    def test_repeated_blocks(self):
        self.assertTrue(strength.has_repeated_block("abcabcabc"))
        self.assertTrue(strength.has_repeated_block("passpasspass"))
        self.assertFalse(strength.has_repeated_block("abcdefghij"))

    def test_common_password_variants(self):
        self.assertTrue(strength.matches_common_password("Password1"))
        self.assertTrue(strength.matches_common_password("P@ssw0rd!"))
        self.assertTrue(strength.matches_common_password("drowssap"))
        self.assertFalse(strength.matches_common_password("kR7#mQ2!xL9$"))

    def test_year_detection(self):
        self.assertTrue(strength.looks_like_a_year("1999"))
        self.assertTrue(strength.looks_like_a_year("2026"))
        self.assertFalse(strength.looks_like_a_year("1800"))
        self.assertFalse(strength.looks_like_a_year("abcd"))

    def test_site_name_in_password(self):
        self.assertTrue(strength.matches_site_or_user("github2026", site="GitHub"))
        self.assertTrue(strength.matches_site_or_user(
            "amit-secret", username="amit@example.com"
        ))
        self.assertFalse(strength.matches_site_or_user("kR7#mQ2!", site="GitHub"))


class EntropyTests(unittest.TestCase):

    def test_pool_size(self):
        self.assertEqual(strength.character_pool_size("abc"), 26)
        self.assertEqual(strength.character_pool_size("aB1!"), 26 + 26 + 10 + 33)
        self.assertEqual(strength.character_pool_size(""), 0)

    def test_bits_scale_with_length(self):
        short = strength.entropy_bits("aB3!")
        long = strength.entropy_bits("aB3!aB3!aB3!aB3!")
        self.assertGreater(long, short)

    def test_crack_time_is_long_for_strong_passwords(self):
        result = strength.analyse("kR7#mQ2!xL9$vT4&zB8@pW6^")
        combined = (result["crack_times"]["fast_hash"]
                    + result["crack_times"]["slow_hash"]
                    + result["crack_times"]["online"]
                    + result["crack_times"]["throttled"])
        self.assertIn("universe", combined)

    def test_crack_time_is_short_for_bad_passwords(self):
        result = strength.analyse("123456")
        self.assertIn("instantly", result["crack_times"]["fast_hash"])

    def test_human_crack_time_extremes(self):
        self.assertEqual(strength.human_crack_time(0.1), "instantly")
        self.assertIn("universe", strength.human_crack_time(10 ** 25))


class AdviceTests(unittest.TestCase):

    def test_problems_and_suggestions_are_produced(self):
        result = strength.analyse("aaaaaa")
        self.assertTrue(result["problems"])
        self.assertTrue(result["suggestions"])

    def test_acceptable_password(self):
        ok, reason = strength.password_is_acceptable("kR7#mQ2!xL9$vT4&")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_unacceptable_passwords(self):
        ok, reason = strength.password_is_acceptable("")
        self.assertFalse(ok)
        self.assertIn("empty", reason.lower())

        ok, reason = strength.password_is_acceptable("password123")
        self.assertFalse(ok)


class MaskTests(unittest.TestCase):

    def test_mask_hides_everything_by_default(self):
        self.assertEqual(strength.mask("secret"), "******")

    def test_mask_can_show_a_prefix(self):
        self.assertEqual(strength.mask("secret", 2), "se****")

    def test_mask_edge_cases(self):
        self.assertEqual(strength.mask(""), "(empty)")
        self.assertEqual(strength.mask("ab", 5), "ab")
