import json
from pathlib import Path
import unittest

from canvasstability import canvas_stability_evidence


class CanvasStabilityTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixture_path = Path(__file__).parent.parent / "test/fixtures/canvas-stability.json"
        fixtures = json.loads(fixture_path.read_text())
        for fixture in fixtures["cases"]:
            with self.subTest(fixture["name"]):
                before = json.dumps(fixture, sort_keys=True)
                actual = canvas_stability_evidence(fixture["signals"])
                self.assertEqual(actual, fixture["expected"])
                self.assertEqual(json.dumps(fixture, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
