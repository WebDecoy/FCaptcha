"""Bounded Web Bot Auth verification for the Python server.

The cryptographic primitive is RFC 9421 (``http-message-signatures``); this
module supplies the Web Bot Auth profile and the untrusted key-discovery
boundary around it.  Discovery failure is deliberately not forgery.  Only a
key that was resolved for the claimed agent and then rejected the signature is
affirmative evidence of a forged claim.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import timedelta
from types import SimpleNamespace
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

import http_sf
from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver
from http_message_signatures.algorithms import ED25519, RSA_PSS_SHA512


VERIFY_TIMEOUT_SECONDS = 3.0
MAX_SIGNATURE_HEADER_BYTES = 16 * 1024
MAX_SIGNATURES = 8
MAX_AGENT_HEADER_BYTES = 2048
MAX_DIRECTORY_BYTES = 256 * 1024
MAX_DIRECTORY_KEYS = 64
MAX_KEY_FIELD_BYTES = 4096
MAX_CACHE_ENTRIES = 16
CACHE_TTL_SECONDS = 60 * 60
FAILURE_RETRY_SECONDS = 30
MAX_SIGNATURE_LIFETIME_SECONDS = 24 * 60 * 60
WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory"
REQUIRED_TAG = "web-bot-auth"


class DiscoveryFailure(Exception):
    """A non-cryptographic failure that must degrade to unverified presence."""


class _ResolvedKey(HTTPSignatureKeyResolver):
    def __init__(self, key):
        self.key = key

    def resolve_public_key(self, key_id: str):
        return self.key


class _HeaderFields:
    """Minimal RFC 9421 header interface that preserves repeated field lines."""

    def __init__(self, fields: Iterable[tuple[str, str]]):
        self._fields = tuple(fields)

    def items(self):
        return iter(self._fields)


@dataclass(frozen=True)
class _Candidate:
    label: str
    key_id: str
    algorithm: str | None
    created: int
    expires: int
    agent: str
    fetch_url: str
    required_component: str


@dataclass
class _CacheEntry:
    keys: list[dict] | None
    stored_at: float


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to the address that passed the SSRF guard."""

    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _presence(agent: str) -> dict:
    return {
        "category": "declared_ai",
        "score": 0.4,
        "confidence": 0.95,
        "reason": f"Signed agent request (Web Bot Auth, unverified): {agent}",
        "details": {"signatureAgent": agent, "verified": False},
    }


def _verified(candidate: _Candidate) -> dict:
    return {
        "category": "declared_ai",
        "score": 0.5,
        "confidence": 0.99,
        "reason": f"Verified AI agent (Web Bot Auth): {candidate.agent}",
        "details": {
            "signatureAgent": candidate.agent,
            "verified": True,
            "keyId": candidate.key_id,
            "algorithm": candidate.algorithm or "",
        },
    }


def _forged(agent: str) -> dict:
    return {
        "category": "bot",
        "score": 0.5,
        "confidence": 0.5,
        "reason": f"Forged Web Bot Auth signature (crypto verification failed): {agent}",
        "details": {"signatureAgent": agent, "verified": False},
    }


def _b64url(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_KEY_FIELD_BYTES:
        raise DiscoveryFailure("invalid JWK field")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise DiscoveryFailure("invalid JWK base64url") from exc


def _thumbprint(jwk: dict) -> str:
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        members = {"crv": "Ed25519", "kty": "OKP", "x": jwk.get("x")}
    elif jwk.get("kty") == "RSA":
        members = {"e": jwk.get("e"), "kty": "RSA", "n": jwk.get("n")}
    else:
        raise DiscoveryFailure("unsupported JWK type")
    if any(not isinstance(value, str) for value in members.values()):
        raise DiscoveryFailure("incomplete JWK")
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def _public_key(jwk: dict):
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        raw = _b64url(jwk.get("x"))
        if len(raw) != 32:
            raise DiscoveryFailure("invalid Ed25519 key length")
        return ED25519, ed25519.Ed25519PublicKey.from_public_bytes(raw)
    if jwk.get("kty") == "RSA":
        modulus = int.from_bytes(_b64url(jwk.get("n")), "big")
        exponent = int.from_bytes(_b64url(jwk.get("e")), "big")
        if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
            raise DiscoveryFailure("unsafe RSA key")
        return RSA_PSS_SHA512, rsa.RSAPublicNumbers(exponent, modulus).public_key()
    raise DiscoveryFailure("unsupported JWK type")


def _is_crypto_failure(exc: BaseException) -> bool:
    seen = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, CryptoInvalidSignature):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _parse_dictionary(value: str) -> dict:
    try:
        parsed = http_sf.parse(value.encode("ascii"), tltype="dictionary")
    except Exception as exc:
        raise DiscoveryFailure("malformed Structured Field dictionary") from exc
    if not isinstance(parsed, dict):
        raise DiscoveryFailure("Structured Field is not a dictionary")
    return parsed


def _agent_members(raw: str) -> tuple[dict[str, tuple[str, dict]], bool]:
    """Return label -> (URI, params), plus whether this is the legacy bare form."""
    value = raw.strip()
    if value.startswith('"'):
        # The legacy form is one Structured Field String. Decode its two legal
        # escapes without accepting trailing members or control characters.
        out = []
        escaped = False
        for index, char in enumerate(value[1:], start=1):
            if escaped:
                if char not in ('"', "\\"):
                    raise DiscoveryFailure("invalid Signature-Agent escape")
                out.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                if value[index + 1 :].strip():
                    raise DiscoveryFailure("trailing Signature-Agent data")
                return {"": ("".join(out), {})}, True
            elif ord(char) < 0x20 or ord(char) > 0x7E:
                raise DiscoveryFailure("invalid Signature-Agent character")
            else:
                out.append(char)
        raise DiscoveryFailure("unterminated Signature-Agent")

    members = {}
    for label, pair in _parse_dictionary(value).items():
        member, params = pair
        if not isinstance(member, str):
            raise DiscoveryFailure("Signature-Agent member is not a string")
        members[label] = (member, dict(params))
    return members, False


def _key_source(agent: str, params: dict) -> str:
    parsed = urlsplit(agent)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DiscoveryFailure("Signature-Agent is not a safe HTTPS URL")
    if parsed.fragment:
        parsed = parsed._replace(fragment="")

    discovery_type = str(params.get("type", "")).lower()
    if discovery_type not in ("", "directory", "jwks_uri", "cimd"):
        raise DiscoveryFailure("unsupported Signature-Agent discovery type")
    if discovery_type == "directory" or (
        discovery_type == "" and parsed.path in ("", "/") and not parsed.query
    ):
        parsed = parsed._replace(path=WELL_KNOWN_DIRECTORY, query="")
    return urlunsplit(parsed)


def _covered_component(component, name: str, key: str | None = None) -> bool:
    bare, params = component
    if bare != name:
        return False
    params = dict(params)
    return key is None or params.get("key") == key


def _parse_candidates(signature_input: str, signature_agent: str) -> list[_Candidate]:
    if len(signature_input.encode("utf-8")) > MAX_SIGNATURE_HEADER_BYTES:
        raise DiscoveryFailure("Signature-Input exceeds size limit")
    if len(signature_agent.encode("utf-8")) > MAX_AGENT_HEADER_BYTES:
        raise DiscoveryFailure("Signature-Agent exceeds size limit")
    members, legacy = _agent_members(signature_agent)
    inputs = _parse_dictionary(signature_input)
    if len(inputs) > MAX_SIGNATURES:
        raise DiscoveryFailure("too many signatures")

    candidates = []
    for label, pair in inputs.items():
        components, params = pair
        params = dict(params)
        if params.get("tag") != REQUIRED_TAG or not isinstance(components, list):
            continue
        created, expires, key_id = params.get("created"), params.get("expires"), params.get("keyid")
        if type(created) is not int or type(expires) is not int or not isinstance(key_id, str):
            continue
        if expires < created or expires - created > MAX_SIGNATURE_LIFETIME_SECONDS:
            continue
        required_component = next((
            name for name in ("@authority", "@target-uri")
            if any(_covered_component(component, name) for component in components)
        ), None)
        if required_component is None:
            continue

        agent_entry = members.get(label) or (members.get("") if legacy else None)
        if not agent_entry:
            continue
        agent, agent_params = agent_entry
        required_key = None if legacy else label
        if not any(_covered_component(component, "signature-agent", required_key) for component in components):
            # Protocol-00 signed the whole dictionary; retain that deployed form.
            if not any(_covered_component(component, "signature-agent") for component in components):
                continue
        candidates.append(_Candidate(
            label=label,
            key_id=key_id,
            algorithm=params.get("alg") if isinstance(params.get("alg"), str) else None,
            created=created,
            expires=expires,
            agent=agent,
            fetch_url=_key_source(agent, agent_params),
            required_component=required_component,
        ))
    return candidates


class WebBotAuthVerifier:
    def __init__(self, fetch_json: Callable[[str, float], dict] | None = None):
        self._fetch_json_override = fetch_json
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(8)
        self._dns_slots = threading.BoundedSemaphore(4)
        self._dns = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="wba-dns")

    @staticmethod
    def _display_agent(raw: str | None) -> str:
        if not raw:
            return "unknown"
        try:
            members, _ = _agent_members(raw)
            first = next(iter(members.values()), None)
            return first[0] if first else "unknown"
        except DiscoveryFailure:
            return "unknown"

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DiscoveryFailure("verification timed out")
        return remaining

    @staticmethod
    def _public_address(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
            if getattr(address, "ipv4_mapped", None):
                address = address.ipv4_mapped
            return address.is_global and not address.is_multicast and not address.is_reserved
        except ValueError:
            return False

    def _resolve(self, host: str, port: int, deadline: float) -> str:
        if not self._dns_slots.acquire(blocking=False):
            raise DiscoveryFailure("directory DNS capacity reached")
        try:
            future = self._dns.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
        except Exception:
            self._dns_slots.release()
            raise
        future.add_done_callback(lambda _future: self._dns_slots.release())
        try:
            answers = future.result(timeout=self._remaining(deadline))
        except Exception as exc:
            future.cancel()
            raise DiscoveryFailure("directory DNS resolution failed") from exc
        for answer in answers:
            address = answer[4][0]
            if self._public_address(address):
                return address
        raise DiscoveryFailure("directory resolved only to non-public addresses")

    def _fetch_json(self, url: str, deadline: float) -> dict:
        if self._fetch_json_override:
            return self._fetch_json_override(url, deadline)
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise DiscoveryFailure("invalid directory URL")
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or 443
        address = self._resolve(host, port, deadline)
        connection = _PinnedHTTPSConnection(host, port, address, self._remaining(deadline))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request("GET", path, headers={
                "Accept": "application/http-message-signatures-directory+json, application/jwk-set+json, application/json",
                "Host": parsed.netloc,
            })
            response = connection.getresponse()
            if response.status != 200:
                raise DiscoveryFailure(f"directory returned {response.status}")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type and content_type not in {
                "application/http-message-signatures-directory+json",
                "application/jwk-set+json",
                "application/json",
            }:
                raise DiscoveryFailure("directory has an unsupported content type")
            if connection.sock:
                connection.sock.settimeout(self._remaining(deadline))
            body = response.read(MAX_DIRECTORY_BYTES + 1)
            if len(body) > MAX_DIRECTORY_BYTES:
                raise DiscoveryFailure("directory exceeds size limit")
            document = json.loads(body.decode("utf-8"))
            if not isinstance(document, dict):
                raise DiscoveryFailure("directory is not a JSON object")
            return document
        except DiscoveryFailure:
            raise
        except Exception as exc:
            raise DiscoveryFailure("directory fetch failed") from exc
        finally:
            connection.close()

    def _load_keys(self, candidate: _Candidate, deadline: float) -> list[dict]:
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(candidate.fetch_url)
            if cached and cached.keys is not None and now - cached.stored_at < CACHE_TTL_SECONDS:
                self._cache.move_to_end(candidate.fetch_url)
                return cached.keys
            if cached and cached.keys is None and now - cached.stored_at < FAILURE_RETRY_SECONDS:
                raise DiscoveryFailure("directory temporarily unavailable")

        if not self._slots.acquire(blocking=False):
            raise DiscoveryFailure("directory fetch capacity reached")
        try:
            document = self._fetch_json(candidate.fetch_url, deadline)
            # Protocol-00 CIMD documents may embed or point to a JWK Set. The
            # nested URL is subjected to the same guard and deadline.
            if "keys" not in document and isinstance(document.get("jwks"), dict):
                document = document["jwks"]
            elif "keys" not in document and isinstance(document.get("jwks_uri"), str):
                document = self._fetch_json(_key_source(document["jwks_uri"], {}), deadline)
            raw_keys = document.get("keys")
            if not isinstance(raw_keys, list) or len(raw_keys) > MAX_DIRECTORY_KEYS:
                raise DiscoveryFailure("invalid directory key set")
            keys = []
            for raw in raw_keys:
                if not isinstance(raw, dict):
                    raise DiscoveryFailure("invalid directory key")
                key = {}
                for field in ("kty", "kid", "alg", "crv", "x", "n", "e", "use", "nbf", "exp"):
                    value = raw.get(field)
                    if value is None:
                        continue
                    if field in ("nbf", "exp"):
                        if type(value) is not int:
                            raise DiscoveryFailure("invalid key validity bound")
                    elif not isinstance(value, str) or len(value) > MAX_KEY_FIELD_BYTES:
                        raise DiscoveryFailure("invalid key field")
                    key[field] = value
                keys.append(key)
            with self._cache_lock:
                self._cache[candidate.fetch_url] = _CacheEntry(keys, now)
                self._cache.move_to_end(candidate.fetch_url)
                while len(self._cache) > MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
            return keys
        except Exception:
            with self._cache_lock:
                self._cache[candidate.fetch_url] = _CacheEntry(None, now)
                self._cache.move_to_end(candidate.fetch_url)
                while len(self._cache) > MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
            raise
        finally:
            self._slots.release()

    def _resolve_key(self, candidate: _Candidate, deadline: float):
        now = int(time.time())
        for jwk in self._load_keys(candidate, deadline):
            try:
                if _thumbprint(jwk) != candidate.key_id:
                    continue
                nbf, exp = jwk.get("nbf", 0), jwk.get("exp", 0)
                if nbf > 1_000_000_000_000:
                    nbf //= 1000
                if exp > 1_000_000_000_000:
                    exp //= 1000
                if (nbf and now < nbf) or (exp and now > exp):
                    raise DiscoveryFailure("directory key is outside its validity window")
                algorithm, key = _public_key(jwk)
                if candidate.algorithm and candidate.algorithm != algorithm.algorithm_id:
                    raise DiscoveryFailure("signature algorithm does not match key type")
                return algorithm, key
            except DiscoveryFailure:
                continue
        raise DiscoveryFailure("keyid not found in directory")

    def verify(self, method: str, url: str, headers: Iterable[tuple[str, str]]) -> list[dict]:
        fields = tuple((str(name), str(value)) for name, value in headers)
        combined = {}
        for name, value in fields:
            lower = name.lower()
            combined[lower] = f"{combined[lower]}, {value}" if lower in combined else value
        if not combined.get("signature") or not combined.get("signature-input"):
            return []

        agent = self._display_agent(combined.get("signature-agent"))
        presence = [_presence(agent)]
        if not combined.get("signature-agent"):
            return presence
        if sum(len(combined.get(name, "").encode("utf-8")) for name in ("signature", "signature-input")) > MAX_SIGNATURE_HEADER_BYTES:
            return presence

        try:
            candidates = _parse_candidates(combined["signature-input"], combined["signature-agent"])
        except DiscoveryFailure:
            return presence
        if not candidates:
            return presence

        message = SimpleNamespace(method=method.upper(), url=url, headers=_HeaderFields(fields))
        deadline = time.monotonic() + VERIFY_TIMEOUT_SECONDS
        crypto_failed = False
        for candidate in candidates:
            try:
                algorithm, key = self._resolve_key(candidate, deadline)
                verifier = HTTPMessageVerifier(
                    signature_algorithm=algorithm,
                    key_resolver=_ResolvedKey(key),
                )
                verifier.verify(
                    message,
                    max_age=timedelta(days=1),
                    expect_tag=REQUIRED_TAG,
                    expect_label=candidate.label,
                    require_components=(candidate.required_component,),
                )
                return [_verified(candidate)]
            except Exception as exc:
                crypto_failed = crypto_failed or _is_crypto_failure(exc)
        return [_forged(agent)] if crypto_failed else presence


VERIFIER = WebBotAuthVerifier()


def request_detections(method: str, url: str, headers: Iterable[tuple[str, str]]) -> list[dict]:
    """Verify one inbound HTTP request with the process-wide bounded cache."""
    return VERIFIER.verify(method, url, headers)

