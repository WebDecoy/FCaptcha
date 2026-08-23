import unittest

from config import INSECURE_DEFAULT_SECRET, signing_secret_from_env


class SigningSecretConfigTests(unittest.TestCase):
    def test_missing_secret_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "FCAPTCHA_SECRET is required"):
            signing_secret_from_env({})

    def test_public_secret_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "FCAPTCHA_SECRET is required"):
            signing_secret_from_env({"FCAPTCHA_SECRET": INSECURE_DEFAULT_SECRET})

    def test_configured_secret_is_returned(self):
        self.assertEqual(signing_secret_from_env({"FCAPTCHA_SECRET": "a-real-deployment-secret"}), "a-real-deployment-secret")

    def test_explicit_development_mode_allows_public_secret(self):
        self.assertEqual(signing_secret_from_env({"FCAPTCHA_INSECURE_DEV_MODE": "1"}), INSECURE_DEFAULT_SECRET)


if __name__ == "__main__":
    unittest.main()
