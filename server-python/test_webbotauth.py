"""Web Bot Auth cryptographic and trust-outcome tests.

All keys are generated per test process and directory reads are injected. No
live identity, endpoint, or network request is involved.
"""

import base64
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ed25519
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver
from http_message_signatures.algorithms import ED25519

from testkit import TestRegistry
from webbotauth import DiscoveryFailure, WebBotAuthVerifier, _thumbprint


test = TestRegistry()
AGENT = "https://agent.example"
TARGET = "https://example.com/api/verify"


class _PrivateKey(HTTPSignatureKeyResolver):
    def __init__(self, key):
        self.key = key

    def resolve_private_key(self, key_id: str):
        return self.key


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _key_pair():
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public)}
    return private, jwk, _thumbprint(jwk)


def _signed(private, key_id, *, agent_header=f'"{AGENT}"'):
    message = SimpleNamespace(
        method="POST",
        url=TARGET,
        headers={"host": "example.com", "signature-agent": agent_header},
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=_PrivateKey(private))
    covered = ("@authority", "signature-agent")
    if not agent_header.startswith('"'):
        covered = ("@authority", '"signature-agent";key="sig1"')
    signer.sign(
        message,
        key_id=key_id,
        created=now,
        expires=now + datetime.timedelta(minutes=5),
        label="sig1",
        tag="web-bot-auth",
        covered_component_ids=covered,
    )
    return list(message.headers.items())


def _verifier(document):
    def fetch(_url, _deadline):
        if isinstance(document, Exception):
            raise document
        return document
    return WebBotAuthVerifier(fetch)


def _outcome(name, detection):
    fixture = json.loads(
        (Path(__file__).parents[1] / "test" / "fixtures" / "web-bot-auth-outcomes.json").read_text()
    )
    expected = next(case for case in fixture["cases"] if case["name"] == name)
    assert detection["category"] == expected["expectedCategory"]
    assert detection["details"]["verified"] is expected["expectedVerified"]
    assert expected["reasonContains"].lower() in detection["reason"].lower()


@test
def verified_signature_earns_verified_identity():
    private, jwk, key_id = _key_pair()
    detection = _verifier({"keys": [jwk]}).verify("POST", TARGET, _signed(private, key_id))[0]
    _outcome("verified", detection)
    assert detection["details"]["keyId"] == key_id
    assert detection["details"]["algorithm"] == "ed25519"


@test
def protocol_01_dictionary_member_is_bound_and_verified():
    private, jwk, key_id = _key_pair()
    headers = _signed(private, key_id, agent_header=f'sig1="{AGENT}"')
    detection = _verifier({"keys": [jwk]}).verify("POST", TARGET, headers)[0]
    assert detection["details"]["verified"] is True


@test
def cryptographic_rejection_is_the_only_forgery_outcome():
    private, jwk, key_id = _key_pair()
    headers = _signed(private, key_id)
    changed_authority = "https://attacker.example/api/verify"
    detection = _verifier({"keys": [jwk]}).verify("POST", changed_authority, headers)[0]
    _outcome("invalid-signature", detection)


@test
def unknown_key_stays_untrusted_without_accusing():
    private, _jwk, key_id = _key_pair()
    _other_private, other_jwk, _other_id = _key_pair()
    detection = _verifier({"keys": [other_jwk]}).verify("POST", TARGET, _signed(private, key_id))[0]
    _outcome("unknown-key", detection)


@test
def unavailable_directory_stays_untrusted_without_accusing():
    private, _jwk, key_id = _key_pair()
    detection = _verifier(DiscoveryFailure("offline")).verify("POST", TARGET, _signed(private, key_id))[0]
    _outcome("unavailable-verifier", detection)


@test
def unsupported_or_unbounded_claims_never_become_verified():
    private, jwk, key_id = _key_pair()
    headers = _signed(private, key_id)
    headers = [
        (name, value.replace('tag="web-bot-auth"', 'tag="other-protocol"'))
        if name.lower() == "signature-input" else (name, value)
        for name, value in headers
    ]
    detection = _verifier({"keys": [jwk]}).verify("POST", TARGET, headers)[0]
    assert detection["details"]["verified"] is False
    assert detection["category"] == "declared_ai"


@test
def no_signature_has_no_web_bot_auth_detection():
    assert _verifier({"keys": []}).verify("POST", TARGET, [("host", "example.com")]) == []


WebBotAuthTests = test.testcase("WebBotAuthTests")


if __name__ == "__main__":
    test.main()
