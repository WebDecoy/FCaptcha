import json
import math
from pathlib import Path
import unittest

from detection import analyze_form_interaction

CADENCE_REASON = "Keystroke cadence analysis"


def close(a, b):
    return math.isclose(a, b, rel_tol=0, abs_tol=1e-9)


class KeystrokeCadenceTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixtures = json.loads((Path(__file__).parent.parent / "test/fixtures/keystroke-cadence.json").read_text())
        for f in fixtures["cases"]:
            with self.subTest(f["name"]):
                form = {"textareaKeyboard": {"message": f["stats"]}}
                got = next((d for d in analyze_form_interaction(form, True) if d["reason"].startswith(CADENCE_REASON)), None)
                want = f["expected"]
                if want is None:
                    self.assertIsNone(got, f"cadence fired: {got}")
                    continue
                self.assertIsNotNone(got, "cadence did not fire")
                self.assertEqual(got["category"], "bot")
                self.assertTrue(close(got["score"], want["score"]), f"score {got['score']}, want {want['score']}")
                self.assertTrue(close(got["confidence"], want["confidence"]), f"confidence {got['confidence']}, want {want['confidence']}")
                details = got["details"]
                self.assertTrue(close(details["cadenceHumanScore"], want["cadenceHumanScore"]),
                                f"cadenceHumanScore {details['cadenceHumanScore']}, want {want['cadenceHumanScore']}")
                self.assertEqual(sorted(details["metrics"]), sorted(want["metrics"]))
                for k, w in want["metrics"].items():
                    self.assertTrue(close(details["metrics"][k], w), f"metric {k} {details['metrics'][k]}, want {w}")


if __name__ == "__main__":
    unittest.main()
