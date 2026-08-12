#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests de régression pour timing-attack.py.

Rapides et fiables : on surcharge le délai (TIMING_SLEEP) et on choisit un
nombre d'essais tel que `rounds * TIMING_SLEEP` reste très au-dessus du bruit
de mesure, sans faire durer les tests.
"""

import importlib.util
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

# Petite mais suffisante : rounds * TIMING_SLEEP = 5 * 0.005 = 0.025 s.
TIMING_SLEEP = "0.005"
ROUNDS = 5

os.environ["TIMING_SLEEP"] = TIMING_SLEEP
HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "timing-attack.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("timing_attack", MOD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


timing_attack = _load_module()


class TestRobustMeasurement(unittest.TestCase):
    def test_measure_uses_median_to_ignore_one_scheduler_spike(self):
        """Une pause scheduler isolée ne doit pas gonfler toute la mesure."""
        # 3 mesures individuelles : 10 ms, pic aberrant 900 ms, 12 ms.
        perf_values = iter([0.000, 0.010, 1.000, 1.900, 2.000, 2.012])
        with patch.object(timing_attack.time, "perf_counter",
                          side_effect=lambda: next(perf_values)), \
             patch.object(timing_attack, "check_password"):
            measured = timing_attack.measure("a", "a", rounds=3)
        self.assertAlmostEqual(measured, 0.012, places=6)


class TestComparisonOracle(unittest.TestCase):
    def test_check_password_exact(self):
        self.assertTrue(timing_attack.check_password("abc", "abc"))

    def test_check_password_wrong_char(self):
        self.assertFalse(timing_attack.check_password("abd", "abc"))

    def test_check_password_wrong_length(self):
        self.assertFalse(timing_attack.check_password("abcd", "abc"))

    def test_matched_count(self):
        # matched_count = nombre d'unités temporelles consommées (= durée).
        # Divergence dès le 1er octet → 1 unité.
        self.assertEqual(timing_attack.matched_count("xyz", "abc"), 1)
        # Divergence au 3e octet → 3 unités.
        self.assertEqual(timing_attack.matched_count("abd", "abc"), 3)
        # Longueur différente → comparaison refusée → 0 unité.
        self.assertEqual(timing_attack.matched_count("abcd", "abc"), 0)
        # Match complet → boucle entière (3) + TERMINAISON SENTINELLE (1) → 4.
        self.assertEqual(timing_attack.matched_count("abc", "abc"), 4)

    def test_sentinel_only_fires_on_exact_match(self):
        """La sentinelle n'ajoute du temps que si guess == secret."""
        # Sans sentinelle, un faux dernier caractère ferait autant d'unités
        # que le bon ; la sentinelle casse cette ambiguïté.
        wrong_last = timing_attack.matched_count("abz", "abc")   # 3 (pas de sent.)
        right_last = timing_attack.matched_count("abc", "abc")   # 4 (sentinelle)
        self.assertEqual(wrong_last, 3)
        self.assertEqual(right_last, 4)


class TestCrackDeterministic(unittest.TestCase):
    def test_crack_recovers_short_secret(self):
        secret = "abc"
        guessed, ok = timing_attack.crack(secret, rounds=ROUNDS)
        self.assertTrue(ok, "timing doit retrouver un secret couvert par CHARSET")
        self.assertEqual(guessed, secret)

    def test_crack_recovers_secret_with_digit(self):
        """Les digits font partie du CHARSET : doivent être retrouvés."""
        secret = "k9z"
        guessed, ok = timing_attack.crack(secret, rounds=ROUNDS)
        self.assertTrue(ok)
        self.assertEqual(guessed, secret)

    def test_crack_recovers_last_char_through_timing(self):
        """Le dernier caractère est retrouvé par le TIMING (sentinelle),
        pas par un oracle d'égalité : on vérifie qu'aucun oracle direct
        n'est utilisé pour le trancher."""
        secret = "ab"
        self.assertFalse(hasattr(timing_attack, "crack_last"),
                         "l'oracle exact du dernier caractère a été retiré")
        guessed, ok = timing_attack.crack(secret, rounds=ROUNDS)
        self.assertTrue(ok)
        self.assertEqual(guessed, secret)

    def test_on_impossible_secret_returns_failure(self):
        """Si le dernier caractère n'est pas dans le CHARSET → échec propre."""
        guessed, ok = timing_attack.crack("ab!", rounds=ROUNDS)
        self.assertFalse(ok)
        self.assertNotEqual(guessed, "ab!")


class TestCLIExitCode(unittest.TestCase):
    def test_success_exits_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "timing-attack.py"), "abc"],
            env={**os.environ, "TIMING_SLEEP": TIMING_SLEEP},
            capture_output=True, text=True, cwd=HERE,
        )
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)

    def test_failure_exits_nonzero(self):
        # CHARSET couvre 'a' et 'b' mais PAS 'x' : le bon caractère de la
        # dernière position n'est pas dispo → timing échoue → exit != 0.
        env = {**os.environ, "TIMING_SLEEP": TIMING_SLEEP,
               "TIMING_CHARSET": "ab"}
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "timing-attack.py"), "abx"],
            env=env, capture_output=True, text=True, cwd=HERE,
        )
        self.assertNotEqual(r.returncode, 0, msg=r.stdout + r.stderr)

    def test_usage_exits_two(self):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "timing-attack.py"),
             "--a", "--b", "--c"],
            env={**os.environ, "TIMING_SLEEP": TIMING_SLEEP},
            capture_output=True, text=True, cwd=HERE,
        )
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
