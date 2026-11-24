import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from server import (
    Detection, ThreatCategory, EXTERNAL_CDP_INPUT_POLICY,
    evaluate_experimental, external_cdp_input_observation,
    _experimental_blocking_enabled,
)


class ExperimentalTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixtures = json.loads((Path(__file__).parent.parent / "test/fixtures/experimental-scoring.json").read_text())
        for f in fixtures["cases"]:
            with self.subTest(f["name"]):
                dets = [Detection(ThreatCategory(d["category"]), d["score"], d["confidence"], "fixture",
                                  non_corroborating=d.get("nonCorroborating", False)) for d in f["detections"]]
                before = json.dumps(f)
                observe = evaluate_experimental(f["signals"], f["productionScore"], dets)
                block = evaluate_experimental(f["signals"], f["productionScore"], dets, True)
                self.assertEqual(observe["observations"].pop(EXTERNAL_CDP_INPUT_POLICY)["mode"], "observe")
                block["observations"].pop(EXTERNAL_CDP_INPUT_POLICY)
                self.assertEqual(observe, f["expected"])
                self.assertEqual(block, {**f["expected"], "mode": "block"})
                self.assertEqual(json.dumps(f), before)

    @staticmethod
    def input_shape():
        return {
            "formAnalysis": {"typing": {
                "inputEvents": 13, "inputsWithoutKeys": 1, "inputsWithoutInputType": 1,
                "selectAllShortcuts": 1, "pasteEvents": 0, "pasteInputs": 0,
            }},
            "behavioral": {"scrollMorphology": {"gestures": 2, "instantRatio": 1}},
        }

    def test_external_cdp_input_observation_accessibility_boundaries(self):
        shape = self.input_shape()
        observation = external_cdp_input_observation(shape)
        self.assertEqual(observation["mode"], "observe")
        self.assertEqual(observation["status"], "detected")
        self.assertEqual([row["id"] for row in observation["detections"]],
                         ["external-cdp-form-input-shape"])

        controls = (
            ("typing", "selectAllShortcuts", 0),  # dictation, autofill, password manager
            ("typing", "inputsWithoutKeys", 0),  # keyboard/screen-reader select-all
            ("typing", "pasteEvents", 1),  # ordinary or assistive paste
            ("scroll", "gestures", 1),  # anchor, switch, or reduced-motion navigation
            ("scroll", "instantRatio", 0.5),  # paired manual-control ceiling
        )
        for section, field, value in controls:
            with self.subTest(section=section, field=field):
                control = self.input_shape()
                target = (control["formAnalysis"]["typing"] if section == "typing"
                          else control["behavioral"]["scrollMorphology"])
                target[field] = value
                self.assertEqual(external_cdp_input_observation(control)["status"], "clear")

        self.assertEqual(external_cdp_input_observation({})["status"], "unknown")
        result = evaluate_experimental(shape, 0.1, [])
        self.assertEqual(result["observations"][EXTERNAL_CDP_INPUT_POLICY]["status"], "detected")
        self.assertEqual(result["score"], 0.1)
        self.assertFalse(result["wouldBlock"])
        self.assertEqual(result["detections"], [])

    def test_blocking_config_requires_current_policy(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_experimental_blocking_enabled())
        for flag in ("", "0", "false", "no", "off", "garbage", "1", "true", "yes", "on", " TRUE ",
                     "stealth-corroboration-v1", " stealth-corroboration-v1 ", "stealth-corroboration-v0",
                     "stealth-corroboration-v2", "animation-consistency-v1", "STEALTH-CORROBORATION-V1", "*", "stealth-corroboration-v1,other"):
            with self.subTest(flag), patch.dict(os.environ, {"FCAPTCHA_EXPERIMENTAL_BLOCKING": flag}):
                self.assertEqual(_experimental_blocking_enabled(), flag in ("stealth-corroboration-v1", " stealth-corroboration-v1 "))


if __name__ == "__main__":
    unittest.main()
