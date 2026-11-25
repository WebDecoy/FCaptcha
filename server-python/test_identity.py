import json
import os
from pathlib import Path
import unittest

from identity import IDENTITY_POLICY, identity_observation
from clientip import ProxyTrust
import server
from server import collect_headers, evaluate_experimental


class _Client:
    def __init__(self, host):
        self.host = host


class _Request:
    def __init__(self, host, headers):
        self.client = _Client(host)
        self.headers = headers


class IdentityCoherenceTests(unittest.TestCase):
    def test_shared_fixtures(self):
        fixtures = json.loads((Path(__file__).parent.parent / "test/fixtures/identity-coherence.json").read_text())
        for f in fixtures["cases"]:
            with self.subTest(f["name"]):
                before = json.dumps(f)
                self.assertEqual(identity_observation(f["signals"], f.get("ja4")), f["expected"])
                # Observe-only even when an operator has opted into a blocking policy.
                self.assertEqual(
                    evaluate_experimental(f["signals"], 0.1, [], True, f.get("ja4"))
                    ["observations"][IDENTITY_POLICY],
                    f["expected"],
                )
                self.assertEqual(json.dumps(f), before, "observations must not mutate inputs")

    def test_ja4_header_requires_trusted_peer(self):
        previous_trust = server.PROXY_TRUST
        previous_headers = os.environ.get("TRUSTED_JA4_HEADERS")
        os.environ["TRUSTED_JA4_HEADERS"] = "x-test-ja4"
        request = _Request("203.0.113.1", {
            "user-agent": "Mozilla/5.0 Chrome/156.0.0.0",
            "x-test-ja4": "t13d1715h2_5b57614c22b0_7121afd63204",
        })
        try:
            server.PROXY_TRUST = ProxyTrust("none")
            self.assertNotIn("x-test-ja4", collect_headers(request))
            server.PROXY_TRUST = ProxyTrust("*")
            self.assertIn("x-test-ja4", collect_headers(request))
        finally:
            server.PROXY_TRUST = previous_trust
            if previous_headers is None:
                os.environ.pop("TRUSTED_JA4_HEADERS", None)
            else:
                os.environ["TRUSTED_JA4_HEADERS"] = previous_headers


if __name__ == "__main__":
    unittest.main()
