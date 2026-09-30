"""Integration contract tests, not a measurement of detection accuracy."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

# A real verifier with ephemeral test-only credentials; never imported by the example app.
for key in list(os.environ):
    if key.startswith('FCAPTCHA_') or key in {'REDIS_URL', 'TRUSTED_PROXIES'}:
        del os.environ[key]
os.environ.update({
    'FCAPTCHA_SECRET': secrets.token_hex(32),
    'FCAPTCHA_VERIFY_SECRET': secrets.token_hex(32),
    'FCAPTCHA_SITE_KEYS': 'fastapi-demo',
    'FCAPTCHA_ALLOWED_HOSTNAMES': '127.0.0.1',
    'TRUSTED_PROXIES': 'none',
})
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'server-python'))
import server as captcha
from main import Settings, create_app

ORIGIN = 'http://127.0.0.1:8790'
SETTINGS = Settings(ORIGIN, 'http://captcha.test', os.environ['FCAPTCHA_VERIFY_SECRET'])


def token(hostname='127.0.0.1', action='contact'):
    return captcha.generate_token('127.0.0.1', 'fastapi-demo', 0.1,
                                  {'hostname': hostname, 'action': action})


@pytest.fixture
def client():
    app = create_app(SETTINGS, transport=httpx.ASGITransport(app=captcha.app))
    with TestClient(app, base_url=ORIGIN, headers={'Origin': ORIGIN}) as browser:
        yield browser


def submit(client, value, **kwargs):
    return client.post('/contact', json={'message': 'Example message', 'token': value}, **kwargs)


def test_accept_then_reject_replay(client):
    value = token()
    response = submit(client, value)
    assert response.status_code == 200
    assert response.json() == {'accepted': True, 'demoOnly': True}
    assert submit(client, value).status_code == 403


@pytest.mark.parametrize('binding', [
    {'hostname': 'other.example'}, {'action': 'login'}, {'hostname': ''}, {'action': ''},
])
def test_reject_wrong_or_missing_binding(client, binding):
    assert submit(client, token(**binding)).status_code == 403


def test_reject_forged_and_expired(client):
    assert submit(client, 'not-a-token').status_code == 403
    value = token()
    data = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
    data['timestamp'] = int(time.time()) - 301
    data.pop('sig')
    data['sig'] = hmac.new(captcha.SECRET_KEY.encode(),
                           captcha._canonical_payload(data).encode(), hashlib.sha256).hexdigest()
    expired = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    assert submit(client, expired).status_code == 403


@pytest.mark.parametrize('body', [
    {}, {'message': 'Test'}, {'message': 'Test', 'token': ''},
    {'message': '  ', 'token': 'unused'}, {'message': 'x' * 2001, 'token': 'unused'},
    {'message': 'Test', 'token': 'x' * 8193}, {'message': 123, 'token': 'unused'},
    {'message': 'Test', 'token': 'unused', 'extra': True},
])
def test_invalid_input(client, body):
    response = client.post('/contact', json=body)
    assert response.status_code == 422
    assert response.json() == {'detail': 'invalid_input'}


def test_request_boundaries(client):
    assert submit(client, token(), headers={'Origin': 'https://other.example'}).status_code == 403
    assert submit(client, token(), headers={'Origin': ''}).status_code == 403
    assert client.post('/contact', content='{}', headers={'Content-Type': 'text/plain'}).status_code == 415
    assert client.post('/contact', content='{', headers={'Content-Type': 'application/json'}).status_code == 422
    assert client.post('/contact', content=b'x' * 17000,
                       headers={'Content-Type': 'application/json'}).status_code == 413
    assert client.post('/contact', content=iter([b'x' * 9000, b'x' * 9000]),
                       headers={'Content-Type': 'application/json'}).status_code == 413


def test_no_secrets_in_browser_config(client):
    response = client.get('/config')
    assert response.json() == {'captchaOrigin': 'http://captcha.test', 'siteKey': 'fastapi-demo'}
    assert response.headers['cache-control'] == 'no-store'
    for path in ('/', '/app.js', '/config'):
        assert SETTINGS.verify_secret not in client.get(path).text
        assert captcha.SECRET_KEY not in client.get(path).text
    assert client.get('/main.py').status_code == 404


@pytest.mark.parametrize('result, expected', [
    ({'success': False}, 403), ({'success': 'true'}, 503), ([], 503),
    ({'success': True, 'hostname': '127.0.0.1'}, 403),
])
def test_verifier_contract(result, expected):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=result))
    with TestClient(create_app(SETTINGS, transport=transport), headers={'Origin': ORIGIN}) as client:
        assert submit(client, 'test').status_code == expected


@pytest.mark.parametrize('failure', ['timeout', '500', 'redirect', 'invalid-json'])
def test_verification_unavailable_fails_closed(failure):
    def handler(request):
        assert request.url.path == '/siteverify'
        assert request.headers['content-type'] == 'application/x-www-form-urlencoded'
        if failure == 'timeout':
            raise httpx.ReadTimeout('test timeout', request=request)
        if failure == '500':
            return httpx.Response(500)
        if failure == 'redirect':
            return httpx.Response(302, headers={'Location': 'https://other.example'})
        return httpx.Response(200, text='not JSON')
    with TestClient(create_app(SETTINGS, transport=httpx.MockTransport(handler)),
                    headers={'Origin': ORIGIN}) as client:
        assert submit(client, 'test').status_code == 503


def test_wrong_verification_secret(client):
    wrong = Settings(ORIGIN, 'http://captcha.test', 'wrong-secret')
    with TestClient(create_app(wrong, transport=httpx.ASGITransport(app=captcha.app)),
                    headers={'Origin': ORIGIN}) as other:
        assert submit(other, token()).status_code == 403
