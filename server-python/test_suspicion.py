"""Tests for adaptive challenge cost."""

import unittest

from suspicion import (
    SuspicionLedger,
    compute_challenge_cost,
    BASE_DIFFICULTY,
    BASE_MIN_AGE_MS,
    MAX_MIN_AGE_MS,
    MAX_HITS,
)


class TestChallengeCost(unittest.TestCase):
    def test_clean_source_pays_the_baseline(self):
        """The property that matters most: a visitor who has done nothing wrong
        pays exactly what everyone paid before adaptive cost existed. If this
        drifts, the feature has started taxing the people it was designed not
        to touch."""
        self.assertEqual(
            compute_challenge_cost(0), (BASE_DIFFICULTY, BASE_MIN_AGE_MS)
        )

    def test_cost_escalates_with_strong_verdicts(self):
        for hits, difficulty, min_age in [
            (0, 4, 1500),
            (1, 4, 4000),
            (2, 4, 4000),
            (3, 5, 8000),
            (5, 5, 8000),
            (6, 5, 15000),
            (50, 5, 15000),
        ]:
            with self.subTest(hits=hits):
                self.assertEqual(
                    compute_challenge_cost(hits), (difficulty, min_age)
                )

    def test_difficulty_never_exceeds_five(self):
        """The escalation must stay on the knob an attacker cannot buy their
        way out of. Difficulty 6 costs a native solver about a millisecond and
        a budget phone about sixteen seconds, so reaching it would be a tax on
        slow devices and nothing else."""
        for hits in range(100):
            for dc in (False, True):
                for ex in (False, True):
                    difficulty, min_age = compute_challenge_cost(hits, dc, 1000, ex)
                    self.assertLessEqual(difficulty, 5)
                    self.assertLessEqual(min_age, MAX_MIN_AGE_MS)

    def test_datacenter_moves_time_not_difficulty(self):
        """A datacenter address used to jump straight to difficulty 5, which
        charges a real person on a corporate VPN or iCloud Private Relay
        several seconds of blocked hashing for having a shared IP."""
        difficulty, min_age = compute_challenge_cost(0, is_datacenter=True)
        self.assertEqual(difficulty, BASE_DIFFICULTY)
        self.assertGreater(min_age, BASE_MIN_AGE_MS)

    def test_rate_signals_raise_only_the_time_floor(self):
        busy_difficulty, busy_age = compute_challenge_cost(0, request_count=50)
        self.assertEqual(busy_difficulty, BASE_DIFFICULTY)
        self.assertGreater(busy_age, BASE_MIN_AGE_MS)

        limited_difficulty, limited_age = compute_challenge_cost(
            0, request_count=50, rate_exceeded=True
        )
        self.assertEqual(limited_difficulty, BASE_DIFFICULTY)
        self.assertGreater(limited_age, busy_age)


class TestSuspicionLedger(unittest.TestCase):
    def test_only_strong_verdicts_are_recorded(self):
        """Marginal verdicts are exactly the case where the scoring might be
        wrong about a real person. Recording them would make the next visitor
        from that address wait for a guess."""
        ledger = SuspicionLedger()
        for score in (0.0, 0.3, 0.5, 0.7, 0.79):
            ledger.record("site", "203.0.113.7", score)
        self.assertEqual(ledger.count("site", "203.0.113.7"), 0)

        ledger.record("site", "203.0.113.7", 0.8)
        ledger.record("site", "203.0.113.7", 0.95)
        self.assertEqual(ledger.count("site", "203.0.113.7"), 2)

    def test_scoped_per_site_and_address(self):
        """Suspicion is per site key as well as per address, so one site's
        abusers do not price another site's visitors."""
        ledger = SuspicionLedger()
        for _ in range(6):
            ledger.record("site-a", "203.0.113.7", 0.95)

        self.assertEqual(ledger.count("site-b", "203.0.113.7"), 0)
        self.assertEqual(ledger.count("site-a", "203.0.113.8"), 0)
        self.assertEqual(ledger.count("site-a", "203.0.113.7"), 6)

    def test_empty_address_never_accumulates(self):
        ledger = SuspicionLedger()
        ledger.record("site", "", 0.99)
        self.assertEqual(ledger.count("site", ""), 0)

    def test_none_score_is_ignored(self):
        ledger = SuspicionLedger()
        ledger.record("site", "203.0.113.7", None)
        self.assertEqual(ledger.count("site", "203.0.113.7"), 0)

    def test_retained_hits_are_bounded(self):
        ledger = SuspicionLedger()
        for _ in range(MAX_HITS * 3):
            ledger.record("site", "203.0.113.7", 0.99)

        n = ledger.count("site", "203.0.113.7")
        self.assertEqual(n, MAX_HITS)
        self.assertEqual(compute_challenge_cost(n)[1], MAX_MIN_AGE_MS)


if __name__ == "__main__":
    unittest.main()
