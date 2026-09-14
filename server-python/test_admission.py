import unittest
from unittest.mock import patch

from admission import AdmissionLimiter
import server


class AdmissionTests(unittest.TestCase):
    def test_capacity_preserves_live_quotas_and_recovers(self):
        now = [0]
        limiter = AdmissionLimiter(max_entries=1, clock=lambda: now[0])
        self.assertTrue(limiter.allow("first", 1))
        self.assertFalse(limiter.allow("rotated", 1))
        self.assertFalse(limiter.allow("first", 1))
        now[0] = 61
        self.assertTrue(limiter.allow("rotated", 1))

    def test_replay_marker_is_not_evicted_at_capacity(self):
        with patch.object(server, "SHARED_STATE", None), patch.object(server.time, "time", return_value=1000) as clock:
            store = server.TokenStore(max_entries=1)
            self.assertTrue(store.mark_used("spent"))
            with self.assertRaisesRegex(RuntimeError, "token_store_full"):
                store.mark_used("flood")
            self.assertFalse(store.mark_used("spent"))
            clock.return_value = 1601
            self.assertTrue(store.mark_used("fresh"))

    def test_ip_binding_canonicalization(self):
        self.assertEqual(server.ip_binding("::ffff:192.0.2.1"), server.ip_binding("192.0.2.1"))
        self.assertEqual(server.ip_binding("2001:0db8:0:0::1"), server.ip_binding("2001:db8::1"))
        self.assertEqual(len(server.ip_binding("192.0.2.1")), 64)

    def test_challenge_quota_cannot_be_bypassed_by_site_key_rotation(self):
        with patch.object(server, "SHARED_STATE", None):
            store = server.PoWChallengeStore()
            first = store.generate("first", "192.0.2.50")
            for i in range(127):
                store.generate(str(i), "192.0.2.50")
            with self.assertRaisesRegex(RuntimeError, "quota"):
                store.generate("another", "192.0.2.50")
            self.assertIn(first["challengeId"], store.challenges)
