import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from server import Detection, ThreatCategory, evaluate_experimental, _experimental_blocking_enabled


class ExperimentalTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixtures = json.loads((Path(__file__).parent.parent / "test/fixtures/experimental-scoring.json").read_text())
        for f in fixtures["cases"]:
            with self.subTest(f["name"]):
                dets = [Detection(ThreatCategory(d["category"]), d["score"], d["confidence"], "fixture",
                                  non_corroborating=d.get("nonCorroborating", False)) for d in f["detections"]]
                before = json.dumps(f)
                self.assertEqual(evaluate_experimental(f["signals"], f["productionScore"], dets), f["expected"])
                self.assertEqual(evaluate_experimental(f["signals"], f["productionScore"], dets, True),
                                 {**f["expected"], "mode": "block"})
                self.assertEqual(json.dumps(f), before)

    def test_blocking_config_requires_current_policy(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_experimental_blocking_enabled())
        for flag in ("", "0", "false", "no", "off", "garbage", "1", "true", "yes", "on", " TRUE ",
                     "stealth-corroboration-v1", " stealth-corroboration-v1 ", "stealth-corroboration-v0",
                     "stealth-corroboration-v2", "STEALTH-CORROBORATION-V1", "*", "stealth-corroboration-v1,other"):
            with self.subTest(flag), patch.dict(os.environ, {"FCAPTCHA_EXPERIMENTAL_BLOCKING": flag}):
                self.assertEqual(_experimental_blocking_enabled(), flag in ("stealth-corroboration-v1", " stealth-corroboration-v1 "))


if __name__ == "__main__":
    unittest.main()
