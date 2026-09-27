import json
from pathlib import Path
import unittest

from identity import IDENTITY_POLICY, identity_observation
from server import evaluate_experimental


class IdentityCoherenceTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixtures = json.loads((Path(__file__).parent.parent / "test/fixtures/identity-coherence.json").read_text())
        for f in fixtures["cases"]:
            with self.subTest(f["name"]):
                before = json.dumps(f)
                self.assertEqual(identity_observation(f["signals"]), f["expected"])
                # Observe-only even when an operator has opted into a blocking policy.
                self.assertEqual(evaluate_experimental(f["signals"], 0.1, [], True)["observations"][IDENTITY_POLICY]["mode"], "observe")
                self.assertEqual(json.dumps(f), before, "observations must not mutate inputs")


if __name__ == "__main__":
    unittest.main()
