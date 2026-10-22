"""Tests for the password generator."""

import unittest

from securevault import generator, constants


class RandomPasswordTests(unittest.TestCase):

    def test_length_is_exact(self):
        for length in (8, 12, 20, 32, 64):
            password = generator.generate_password(length=length)
            self.assertEqual(len(password), length)

    def test_contains_every_requested_group(self):
        password = generator.generate_password(length=24)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in constants.SYMBOLS for c in password))

    def test_respects_disabled_groups(self):
        password = generator.generate_password(
            length=30, use_symbols=False, use_upper=False
        )
        self.assertFalse(any(c in constants.SYMBOLS for c in password))
        self.assertFalse(any(c.isupper() for c in password))

    def test_avoid_ambiguous_removes_the_lookalikes(self):
        for _ in range(5):
            password = generator.generate_password(
                length=40, avoid_ambiguous=True
            )
            for character in password:
                self.assertNotIn(character, constants.AMBIGUOUS_CHARACTERS)

    def test_two_passwords_are_not_the_same(self):
        first = generator.generate_password(length=32)
        second = generator.generate_password(length=32)
        self.assertNotEqual(first, second)

    def test_impossible_options_raise(self):
        with self.assertRaises(generator.GeneratorError):
            generator.generate_password(length=3)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_password(length=9999)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_password(
                use_lower=False, use_upper=False, use_digits=False, use_symbols=False
            )

    def test_batch_count(self):
        passwords = generator.generate_batch(5, length=16)
        self.assertEqual(len(passwords), 5)
        self.assertEqual(len(set(passwords)), 5)

    def test_batch_limits(self):
        with self.assertRaises(generator.GeneratorError):
            generator.generate_batch(0)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_batch(21)


class PassphraseTests(unittest.TestCase):

    def test_correct_number_of_words(self):
        phrase = generator.generate_passphrase(5, "-")
        self.assertEqual(len(phrase.split("-")), 5)

    def test_words_come_from_the_list(self):
        phrase = generator.generate_passphrase(4, "-")
        for word in phrase.split("-"):
            self.assertIn(word, constants.WORDLIST)

    def test_number_suffix(self):
        phrase = generator.generate_passphrase(4, "-", add_number=True)
        parts = phrase.split("-")
        self.assertEqual(len(parts), 5)
        self.assertTrue(parts[-1].isdigit())

    def test_capitalise(self):
        phrase = generator.generate_passphrase(3, "-", capitalise=True)
        for word in phrase.split("-"):
            self.assertTrue(word[0].isupper())

    def test_bounds(self):
        with self.assertRaises(generator.GeneratorError):
            generator.generate_passphrase(2)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_passphrase(50)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_passphrase("five")


class PinTests(unittest.TestCase):

    def test_digits_only(self):
        pin = generator.generate_pin(6)
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

    def test_leading_zeros_are_kept(self):
        # Run a few times; if the generator dropped leading zeros, at least
        # one of these would come back short.
        for _ in range(50):
            pin = generator.generate_pin(4)
            self.assertEqual(len(pin), 4)

    def test_bounds(self):
        with self.assertRaises(generator.GeneratorError):
            generator.generate_pin(3)
        with self.assertRaises(generator.GeneratorError):
            generator.generate_pin(30)


class MemorableTests(unittest.TestCase):

    def test_length_and_contents(self):
        password = generator.generate_memorable(16)
        self.assertEqual(len(password), 16)
        self.assertTrue(any(character.isdigit() for character in password))


class PresetTests(unittest.TestCase):

    def test_every_preset_works(self):
        for preset in constants.GENERATOR_PRESETS:
            made = generator.generate_from_preset(preset)
            self.assertIn("password", made)
            self.assertGreater(len(made["password"]), 3)
            self.assertEqual(made["preset"], preset)

    def test_unknown_preset(self):
        with self.assertRaises(generator.GeneratorError):
            generator.generate_from_preset("nonsense")


class PronunciationTests(unittest.TestCase):

    def test_chunks_rebuild_the_original(self):
        password = "abcdefghij"
        chunks = generator.syllables_for_pronunciation(password)
        self.assertEqual("".join(chunks), password)

    def test_empty(self):
        self.assertEqual(generator.syllables_for_pronunciation(""), [])
