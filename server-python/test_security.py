import asyncio
import hashlib
import json
import os
import runpy
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

os.environ.setdefault("FCAPTCHA_SECRET", "security-test-secret")
import server


def clean_signals():
    return {"behavioral": {"totalPoints": 60, "trajectoryLength": 400,
        "microTremorScore": 0.5, "velocityVariance": 0.5, "approachPoints": 12,
        "approachDirectness": 0.4, "explorationRatio": 0.35, "overshootCorrections": 2,
        "interactionDuration": 4200}, "environmental": {"automationFlags": {}},
        "meta": {"challengeNonce": "binding"}}


class SecurityTests(unittest.TestCase):
    def test_launcher_access_logging_is_opt_in(self):
        for flag, expected in (("", False), ("1", True)):
            with patch.dict(os.environ, {"REDIS_URL": "", "FCAPTCHA_LOG_ACCESS": flag}), patch("uvicorn.run") as run:
                runpy.run_path(str(Path(server.__file__)), run_name="__main__")
                self.assertIs(run.call_args.kwargs["access_log"], expected)

    def test_independent_tokens_and_replay(self):
        with patch.object(server.time, "time", return_value=1800000000):
            a = server.generate_token("ip", "site", 0.1)
            b = server.generate_token("ip", "site", 0.1)
            self.assertNotEqual(a, b)
            self.assertTrue(server.verify_token(a)["valid"])
            self.assertFalse(server.verify_token(a)["valid"])
            self.assertTrue(server.verify_token(b)["valid"])

    def test_commitment_and_timing_gate_even_with_clean_signals(self):
        for mode in ("valid", "mismatch", "missing", "early", "elevated"):
            with self.subTest(mode=mode):
                signals = clean_signals()
                raw = json.dumps(signals)
                digest = hashlib.sha256(("other payload" if mode == "mismatch" else raw).encode()).hexdigest()
                proof = server.PoWSolution(challengeId="id", nonce=1, hash="hash", signalsHash=digest)
                verified = {"valid": True, "nonce": "binding", "difficulty": 4,
                    "serverElapsed": 1 if mode == "early" else 2000,
                    "minAgeMs": 60000 if mode == "elevated" else 1500}
                with patch.object(server.pow_store, "verify", return_value=verified):
                    result = server.run_verification(signals, "203.0.113.1", mode,
                        "Mozilla/5.0", {"accept": "text/html", "accept-language": "en-US",
                        "accept-encoding": "gzip", "connection": "keep-alive"},
                        pow_solution=proof, signals_json=None if mode == "missing" else raw)
                self.assertEqual(result["success"], mode == "valid", result)
                if mode != "valid":
                    self.assertIsNone(result["token"])

    def test_fingerprint_bounds_and_expiry(self):
        with patch.object(server.time, "time", return_value=1000) as now:
            store = server.FingerprintStore(max_entries=32)
            for i in range(10000):
                store.record(str(i), "ip", "site")
            self.assertEqual(store.get_ip_fp_count("ip"), 16)
            self.assertEqual(len(store.fingerprints), 16)
            for i in range(100):
                store.record("shared", str(i), "site")
            self.assertEqual(store.get_fp_ip_count("shared", "site"), 16)
            self.assertLessEqual(len(store.ip_fingerprints), 32)
            now.return_value = 2000
            self.assertEqual(store.get_fp_ip_count("shared", "site"), 0)

    def test_redis_work_does_not_block_health_or_event_loop(self):
        async def run():
            started = threading.Event()
            release = threading.Event()

            def blocking_state_call():
                started.set()
                if not release.wait(2):
                    raise AssertionError("event loop blocked behind Redis work")
                return "done"

            with patch.object(server, "SHARED_STATE", object()):
                task = asyncio.create_task(server.run_stateful(blocking_state_call))
                try:
                    while not started.is_set():
                        await asyncio.sleep(0.001)
                    self.assertEqual((await server.health())["status"], "ok")
                finally:
                    release.set()
                self.assertEqual(await task, "done")
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
