from unittest.mock import Mock, patch

import httpx
from django.test import TestCase, override_settings


@override_settings(
    FCAPTCHA_ORIGIN="https://captcha.example",
    FCAPTCHA_VERIFY_SECRET="test-verification-secret",
    FCAPTCHA_EXPECTED_HOSTNAME="testserver",
)
class ContactTests(TestCase):
    def verifier(self, results):
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        client.post.side_effect = [
            Mock(
                json=Mock(return_value=result),
                raise_for_status=Mock(),
            ) for result in results
        ]
        return patch("contact.verifier.httpx.Client", return_value=client), client

    def submit(self, token="signed-token"):
        return self.client.post("/", {"message": "Example message", "fcaptcha_token": token})

    def test_valid_token_accepts_submission(self):
        mocked, client = self.verifier([{
            "success": True, "hostname": "testserver", "action": "contact",
        }])
        with mocked:
            response = self.submit()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sample accepted")
        client.post.assert_called_once_with(
            "/turnstile/v0/siteverify",
            data={"secret": "test-verification-secret", "response": "signed-token"},
        )

    def test_replayed_token_is_rejected(self):
        mocked, _ = self.verifier([
            {"success": True, "hostname": "testserver", "action": "contact"},
            {"success": False, "error-codes": ["invalid-input-response"]},
        ])
        with mocked:
            self.assertEqual(self.submit().status_code, 200)
            self.assertEqual(self.submit().status_code, 403)

    def test_missing_token_never_calls_verifier(self):
        with patch("contact.views.verify_token") as verify:
            response = self.client.post("/", {"message": "Example message"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This field is required")
        verify.assert_not_called()

    def test_wrong_binding_is_rejected(self):
        for result in (
            {"success": True, "hostname": "other.example", "action": "contact"},
            {"success": True, "hostname": "testserver", "action": "login"},
        ):
            mocked, _ = self.verifier([result])
            with mocked:
                self.assertEqual(self.submit().status_code, 403)

    def test_verifier_failure_fails_closed(self):
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        client.post.side_effect = httpx.ReadTimeout("timeout")
        with patch("contact.verifier.httpx.Client", return_value=client):
            self.assertEqual(self.submit().status_code, 503)

    def test_secret_is_not_rendered(self):
        response = self.client.get("/")
        self.assertNotContains(response, "test-verification-secret")
        self.assertContains(response, "https://captcha.example/fcaptcha.js")
