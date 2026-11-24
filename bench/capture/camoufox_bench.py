#!/usr/bin/env python3
"""Capture unmodified browser submissions on a loopback FCaptcha deployment.

Outputs are research artifacts, not additions to the human benchmark corpus.
Automated Firefox is a control, never a human false-positive measurement.
"""

import argparse
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import platform
import random
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
BROWSER_VERSION = "152.0.4-beta.30"
CLIENT_VERSION_PATTERN = re.compile(rb"\bversion\s*:\s*['\"](\d+\.\d+\.\d+)['\"]")
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Browser interaction benchmark</title>
<style>body{font:18px system-ui;margin:32px;max-width:680px}input{font:inherit}
button{padding:14px;margin:20px 0}#filler{height:1200px}</style></head><body>
<h1>Browser interaction benchmark</h1><p>Read this page, move around, and
__FORM_INSTRUCTION__ Scroll down and back, then submit the benchmark. Do not enter
personal data. Form submissions are measured locally and are not stored.</p>
<form id="benchmark" data-fcaptcha-action="benchmark">
__FORM_FIELDS__
<p><a href="#footer">Read more</a></p><div id="captcha"></div>
<button id="submit" type="button" hidden>Submit benchmark</button>
</form><pre id="result"></pre>
<div id="filler"></div><p id="footer">Return to the check above.</p>
__RESEARCH_SCRIPT__<script src="/fcaptcha.js"></script><script>
const options = __OPTIONS__;
FCaptcha.configure({serverUrl: location.origin});
if (options.observations) window.startBrowserObservationCapture();
function show(value) {
  document.querySelector('#result').textContent = JSON.stringify({
    success:value.success, score:value.score, reason:value.reason,
    experimental:value.experimental, tokenIssued:!!value.token
  }, null, 2);
}
if (options.mode === 'form') {
  const form = document.querySelector('#benchmark');
  const button = document.querySelector('#submit');
  button.type = 'submit';
  button.hidden = false;
  const session = FCaptcha.invisible({siteKey:options.siteKey, autoScore:true});
  form.addEventListener('submit', (event) => {
    const token = new FormData(form).get('fcaptcha_token');
    if (!token) return;
    event.preventDefault();
    show(session.lastScore || {success:true, token});
  });
} else if (options.mode === 'invisible') {
  const session = FCaptcha.invisible({siteKey:options.siteKey, autoScore:false});
  const button = document.querySelector('#submit');
  button.hidden = false;
  button.onclick = async () => {
    button.disabled = true;
    try { show(await session.execute('benchmark')); }
    catch (e) { document.querySelector('#result').textContent = e.message; }
  };
} else {
  // The checkbox callback receives the token string, not a result object.
  FCaptcha.render('captcha', {siteKey:options.siteKey, callback:(token) => show({success:true, token})});
}
document.body.dataset.ready = 'true';
</script></body></html>"""

FORM_FIXTURES = {
    'basic': '<label>Sample name <input id="name" name="sample_name" autocomplete="off"></label>',
    'autofill': '''<fieldset><legend>Fictional test profile</legend>
<label>Full name <input id="name" name="name" autocomplete="name"></label>
<label>Email <input name="email" type="email" autocomplete="email"></label>
<label>Street address <input name="street_address" autocomplete="street-address"></label>
<label>Postal code <input name="postal_code" autocomplete="postal-code"></label>
</fieldset>''',
    'credentials': '''<fieldset><legend>Fictional test account</legend>
<label>Username <input id="name" name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
</fieldset>''',
}

FORM_INSTRUCTIONS = {
    'basic': 'enter a made-up name.',
    'autofill': 'fill the fictional profile fields using the workflow under test.',
    'credentials': 'fill the fictional account fields using the workflow under test.',
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def request(url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        response = urllib.request.urlopen(req, timeout=90)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


class CaptureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, backend, mode, observations=False, expected_client_version=None,
                 form_fixture='basic'):
        super().__init__(('127.0.0.1', 0), CaptureHandler)
        self.backend = backend
        self.mode = mode
        self.site_key = 'browser-bench-' + uuid.uuid4().hex
        self.client_ip = '2001:db8:' + ':'.join(uuid.uuid4().hex[i:i+4] for i in range(0, 24, 4))
        self.records = []
        self.requests = []
        self.client_sha256 = None
        self.client_version = None
        self.expected_client_version = expected_client_version
        self.form_fixture = form_fixture
        self.finished = threading.Event()
        self.observations = None
        self.observations_finished = threading.Event()
        self.probe_source = (Path(__file__).with_name('consistency_probe.js').read_bytes()
                             if observations else None)


class CaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, content_type, data):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/':
            options = {'mode': self.server.mode, 'siteKey': self.server.site_key, 'observations': self.server.probe_source is not None}
            script = '<script src="/__research/probe.js"></script>' if self.server.probe_source else ''
            data = (PAGE.replace('__OPTIONS__', json.dumps(options))
                    .replace('__RESEARCH_SCRIPT__', script)
                    .replace('__FORM_FIELDS__', FORM_FIXTURES[self.server.form_fixture])
                    .replace('__FORM_INSTRUCTION__', FORM_INSTRUCTIONS[self.server.form_fixture])
                    .encode())
            return self.respond(200, 'text/html; charset=utf-8', data)
        if self.server.probe_source:
            path = urllib.parse.urlsplit(self.path).path
            if path == '/__research/probe.js':
                return self.respond(200, 'application/javascript', self.server.probe_source)
            if path == '/__research/frame':
                return self.respond(200, 'text/html', b'<!doctype html><body><script src="/__research/probe.js"></script>')
        self.forward()

    def do_POST(self):
        if self.path == '/__research/observations' and self.server.probe_source:
            size = int(self.headers.get('Content-Length', '0'))
            if size > 512_000:
                return self.respond(413, 'text/plain', b'Too large')
            try:
                value = json.loads(self.rfile.read(size))
            except (ValueError, UnicodeDecodeError):
                return self.respond(400, 'text/plain', b'Invalid JSON')
            if not isinstance(value, dict) or not self.server.finished.is_set():
                return self.respond(400, 'text/plain', b'Expected observations after scoring')
            self.server.observations = value
            self.server.observations_finished.set()
            return self.respond(200, 'application/json', b'{"saved":true}')
        self.forward()

    def forward(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in ('/fcaptcha.js', '/api/pow/challenge', '/api/score', '/api/verify'):
            return self.respond(404, 'text/plain', b'Not found')
        size = int(self.headers.get('Content-Length', '0'))
        if size > 2_000_000:
            return self.respond(413, 'text/plain', b'Too large')
        data = self.rfile.read(size) if size else None
        # The local proxy isolates quotas and reputation per sample, preserving
        # browser headers and signal bytes. No fingerprint normalization.
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ('host', 'content-length', 'connection', 'accept-encoding', 'x-forwarded-for')}
        headers['X-Forwarded-For'] = self.server.client_ip
        # Preserve the browser's encoding declaration for header analysis. The
        # backend does not compress these endpoints; do not synthesize values.
        if 'Accept-Encoding' in self.headers:
            headers['Accept-Encoding'] = self.headers['Accept-Encoding']
        req = urllib.request.Request(self.server.backend + self.path, data=data, headers=headers, method=self.command)
        try:
            try:
                response = urllib.request.urlopen(req, timeout=90)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                payload = response.read()
                status = response.status
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
            self.server.requests.append({'method': self.command, 'path': path, 'status': status})
            if path == '/fcaptcha.js':
                self.server.client_sha256 = hashlib.sha256(payload).hexdigest()
                match = CLIENT_VERSION_PATTERN.search(payload)
                self.server.client_version = match.group(1).decode() if match else None
            if path in ('/api/score', '/api/verify'):
                self.server.records.append({
                    'endpoint': path, 'httpStatus': status,
                    'headers': dict(self.headers),
                    'request': json.loads(data), 'response': json.loads(payload),
                })
                self.server.finished.set()
            self.respond(status, content_type, payload)
        except Exception as error:
            self.respond(502, 'text/plain', str(error).encode())


@contextmanager
def capture_server(backend, mode, observations=False, expected_client_version=None,
                   form_fixture='basic'):
    server = CaptureServer(backend, mode, observations, expected_client_version, form_fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f'http://127.0.0.1:{server.server_port}/'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def interact(page, mode, seed):
    rng = random.Random(seed)
    page.locator('body[data-ready=true]').wait_for()
    page.wait_for_timeout(1200)
    # Fixed task, varied timing; this is scripted input, never a human label.
    for x, y in [(90, 130), (420, 170), (230, 95), (510, 210), (140, 240), (370, 120)]:
        page.mouse.move(x + rng.randrange(-12, 13), y + rng.randrange(-12, 13))
        page.wait_for_timeout(rng.randrange(120, 420))
    field = page.locator('#name')
    field.click()
    field.press_sequentially('Browser test', delay=90)
    page.mouse.wheel(0, 450)
    page.wait_for_timeout(500)
    page.mouse.wheel(0, -450)
    page.wait_for_timeout(600)
    target = page.locator('#submit' if mode in ('invisible', 'form') else '#captcha [role=checkbox]')
    target.click()


def finish_capture(server, secret):
    if len(server.records) != 1:
        raise RuntimeError(f'Expected one submission, received {len(server.records)}')
    record = server.records[0]
    result = record['response']
    token = result.pop('token', None)
    record['tokenIssued'] = bool(token)
    record['tokenValid'] = None
    if token:
        status, _, body = request(server.backend + '/api/token/verify', {
            'token': token, 'secret': secret, 'remoteip': server.client_ip,
        }, {'Content-Type': 'application/json'})
        verification = json.loads(body)
        record['tokenVerification'] = verification
        record['tokenValid'] = status == 200 and verification.get('valid') is True
    record['clientIp'] = server.client_ip
    record['clientSha256'] = getattr(server, 'client_sha256', None)
    record['clientVersion'] = getattr(server, 'client_version', None)
    expected_client_version = getattr(server, 'expected_client_version', None)
    if expected_client_version and record['clientVersion'] != expected_client_version:
        raise RuntimeError(
            f"Expected FCaptcha client {expected_client_version}, served "
            f"{record['clientVersion'] or 'an unversioned client'}"
        )
    if record['httpStatus'] != 200:
        raise RuntimeError(f"Scoring HTTP {record['httpStatus']}")
    if result.get('experimental', {}).get('mode') != 'observe':
        raise RuntimeError('Benchmark requires the server in experimental monitoring mode')
    if result.get('success') and not record['tokenValid']:
        raise RuntimeError('Successful verdict did not produce a valid token')
    if not result.get('success') and token:
        raise RuntimeError('Unsuccessful verdict unexpectedly issued a token')
    if result.get('reason') in ('rate_limited', 'pow_not_satisfied', 'hostname_not_allowed'):
        raise RuntimeError('Infrastructure/proof failure: ' + result['reason'])
    return record


def attach_verdict_log(sample, path):
    if not path or 'capture' not in sample:
        return
    capture = sample['capture']
    site_key = capture['request']['siteKey']
    for line in path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get('event') == 'verdict' and entry.get('siteKey') == site_key:
            capture['verdictLog'] = entry
            return
    raise RuntimeError(f'No verdict log matched sample {site_key}')


def attach_failed_captures(sample, server):
    """Retain diagnostics for failed submissions without ever persisting tokens."""
    if not server.records:
        return
    for record in server.records:
        response = record.get('response') or {}
        record['tokenIssued'] = record.get('tokenIssued', bool(response.get('token')))
        response.pop('token', None)
    sample['failedCaptures'] = server.records


def record_operator_outcome(sample, value, actor='browser-internal task'):
    """Keep only an automated task completed without human takeover."""
    outcome = str(value or '').strip().lower()
    if outcome not in ('completed', 'takeover', 'refused'):
        outcome = 'unconfirmed'
    sample['operatorOutcome'] = outcome
    if outcome == 'completed':
        return True
    capture = sample.pop('capture', None)
    if capture:
        sample.setdefault('failedCaptures', []).append(capture)
    sample['error'] = (
        f'{actor} outcome was {outcome}; '
        'only completion without takeover is importable'
    )
    return False


def prompt_operator_outcome(actor='browser-internal agent'):
    print('Scoring submission captured. Enter "completed" only if the named '
          f'{actor} finished the whole task without human takeover.',
          flush=True)
    try:
        return input('Outcome [completed/takeover/refused]: ')
    except EOFError:
        return 'unconfirmed'


def run_case(args, case, index):
    sample = {**case, 'label': 'agent', 'provenance': 'captured',
              'seed': args.seed + index, 'normalization': 'none',
              'startedAt': datetime.now(timezone.utc).isoformat()}
    started = time.monotonic()
    with capture_server(args.server, case['mode'], args.observations,
                        args.expected_client_version) as (server, url):
        try:
            if case['browser'] == 'camoufox':
                from camoufox.sync_api import Camoufox
                manager = Camoufox(browser=args.browser_version, headless=case['headless'],
                                   humanize=case['humanize'], config=copy.deepcopy(args.camoufox_config) or None)
            else:
                from playwright.sync_api import sync_playwright
                manager = sync_playwright()
            with manager as launched:
                if case['browser'] == 'camoufox':
                    browser = launched
                else:
                    prefs = {'privacy.resistFingerprinting': True} if case['privacy'] else {}
                    if case.get('reducedMotion'):
                        prefs['ui.prefersReducedMotion'] = 1
                    browser = launched.firefox.launch(headless=case['headless'], firefox_user_prefs=prefs)
                sample['browserVersion'] = browser.version
                page = browser.new_page()
                page.set_default_timeout(args.timeout * 1000)
                errors = []
                sample['pageErrors'] = errors
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(url)
                interact(page, case['mode'], args.seed + index)
                deadline = time.monotonic() + args.timeout
                while not server.finished.is_set() and time.monotonic() < deadline:
                    page.wait_for_timeout(100)
                if not server.finished.is_set():
                    raise RuntimeError('No scoring request: ' + page.locator('#result').inner_text())
                sample['capture'] = finish_capture(server, args.secret)
                attach_verdict_log(sample, args.verdict_log)
                if args.observations:
                    deadline = time.monotonic() + 25
                    while not server.observations_finished.is_set() and time.monotonic() < deadline:
                        page.wait_for_timeout(100)
                    sample['observations'] = server.observations or {'status': 'timeout'}
                    sample['probeSha256'] = hashlib.sha256(server.probe_source).hexdigest()
                browser.close()
        except Exception as error:
            sample['error'] = str(error)
            # Preserve failures as failures, not detected bots. Never persist tokens.
            attach_failed_captures(sample, server)
        sample['httpRequests'] = server.requests
    sample['durationSeconds'] = round(time.monotonic() - started, 3)
    return sample


def summarize(samples):
    groups = {}
    for sample in samples:
        key = '/'.join(str(sample[k]) for k in ('browser', 'headless', 'humanize', 'privacy', 'mode'))
        if sample.get('reducedMotion'):
            key += '/reduced-motion'
        group = groups.setdefault(key, {'attempts': 0, 'completed': 0, 'errors': 0, 'validTokens': 0,
                                        'experimentalWouldBlock': 0, 'additionalExperimentalBlocks': 0,
                                        'scores': [], 'detections': {}})
        group['attempts'] += 1
        if 'error' in sample:
            group['errors'] += 1
            continue
        group['completed'] += 1
        capture = sample['capture']
        verdict = capture['response']
        group['validTokens'] += int(capture['tokenValid'] is True)
        group['experimentalWouldBlock'] += int(verdict['experimental']['wouldBlock'])
        group['additionalExperimentalBlocks'] += int(verdict['experimental']['wouldBlock'] and verdict['score'] < 0.5)
        group['scores'].append(verdict['score'])
        for detection in capture.get('verdictLog', verdict).get('detections', []):
            reason = detection.get('reason') or json.dumps(detection, sort_keys=True)
            group['detections'][reason] = group['detections'].get(reason, 0) + 1
    return groups


def accessibility_workflow(args):
    """Return validated, operator-declared provenance for a real accessibility capture."""
    if not getattr(args, 'accessibility_manual', False):
        return None

    fields = {
        '--manual-workflow': getattr(args, 'manual_workflow', None),
        '--input-tool-name': getattr(args, 'input_tool_name', None),
        '--input-tool-version': getattr(args, 'input_tool_version', None),
        '--input-tool-settings': getattr(args, 'input_tool_settings', None),
    }
    missing = [name for name, value in fields.items() if not str(value or '').strip()]
    if missing:
        raise ValueError('--accessibility-manual requires ' + ', '.join(missing))
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', args.manual_workflow):
        raise ValueError('--manual-workflow must be a lowercase hyphenated slug')
    if args.form_fixture not in FORM_FIXTURES:
        raise ValueError('--form-fixture must be basic, autofill, or credentials')
    if not getattr(args, 'consent_confirmed', False):
        raise ValueError('--accessibility-manual requires --consent-confirmed')
    if not getattr(args, 'isolated_test_context', False):
        raise ValueError('--accessibility-manual requires --isolated-test-context')

    return {
        'id': args.manual_workflow,
        'fixture': args.form_fixture,
        'tool': {
            'name': args.input_tool_name,
            'version': args.input_tool_version,
            'settings': args.input_tool_settings,
        },
        'consent': 'operator-confirmed',
        'isolation': 'fresh-test-context-no-personal-data',
    }


def manual_capture(args):
    """Serve a page for a person using their own browser, without Playwright."""
    sample = {'browser': args.environment_label, 'label': 'human',
              'inputSource': 'operator-declared manual input', 'provenance': 'captured',
              'headless': False, 'humanize': False, 'privacy': 'operator-described',
              'mode': args.modes[0], 'normalization': 'none'}
    workflow = accessibility_workflow(args)
    if workflow:
        sample['manualWorkflow'] = workflow
    with capture_server(args.server, args.modes[0], args.observations,
                        args.expected_client_version, args.form_fixture) as (server, url):
        print(f'Open {url} in your own browser and complete the page. Waiting {args.timeout}s.', flush=True)
        if not server.finished.wait(args.timeout):
            sample['error'] = 'No manual submission received; human baseline remains unmeasured'
        else:
            try:
                sample['capture'] = finish_capture(server, args.secret)
                attach_verdict_log(sample, args.verdict_log)
                if args.observations:
                    server.observations_finished.wait(25)
                    sample['observations'] = server.observations or {'status': 'timeout'}
                    sample['probeSha256'] = hashlib.sha256(server.probe_source).hexdigest()
            except Exception as error:
                sample['error'] = str(error)
                attach_failed_captures(sample, server)
    return sample


def browser_internal_capture(args):
    """Serve a page for a browser-internal agent without attaching a driver."""
    sample = {'browser': args.environment_label, 'agent': args.agent_label,
              'label': 'agent',
              'inputSource': 'operator-declared browser-internal automation',
              'provenance': 'captured', 'headless': False, 'humanize': False,
              'privacy': 'operator-described', 'mode': args.modes[0],
              'normalization': 'none'}
    with capture_server(args.server, args.modes[0], args.observations,
                        args.expected_client_version) as (server, url):
        print(f'Open {url} in {args.environment_label}, then ask {args.agent_label} '
              f'to complete the page. Waiting {args.timeout}s.', flush=True)
        if not server.finished.wait(args.timeout):
            sample['error'] = 'No browser-internal submission received; class remains unmeasured'
        else:
            try:
                sample['capture'] = finish_capture(server, args.secret)
                attach_verdict_log(sample, args.verdict_log)
                if args.observations:
                    server.observations_finished.wait(25)
                    sample['observations'] = server.observations or {'status': 'timeout'}
                    sample['probeSha256'] = hashlib.sha256(server.probe_source).hexdigest()
                record_operator_outcome(sample, prompt_operator_outcome())
            except Exception as error:
                sample['error'] = str(error)
                attach_failed_captures(sample, server)
    return sample


def external_driver_capture(args):
    """Serve a page for an operator-started external browser automation driver."""
    driver = {'name': args.driver_name, 'version': args.driver_version,
              'commit': args.driver_commit}
    sample = {'browser': args.environment_label, 'driver': driver,
              'label': 'agent',
              'inputSource': 'operator-declared external browser automation',
              'provenance': 'captured', 'headless': False, 'humanize': False,
              'privacy': 'operator-described', 'mode': args.modes[0],
              'normalization': 'none'}
    with capture_server(args.server, args.modes[0], args.observations,
                        args.expected_client_version) as (server, url):
        print(f'Direct {args.driver_name} {args.driver_version} ({args.driver_commit}) '
              f'in {args.environment_label} to {url} and have it complete the page. '
              f'Waiting {args.timeout}s.', flush=True)
        if not server.finished.wait(args.timeout):
            sample['error'] = 'No external-driver submission received; class remains unmeasured'
        else:
            try:
                sample['capture'] = finish_capture(server, args.secret)
                attach_verdict_log(sample, args.verdict_log)
                if args.observations:
                    server.observations_finished.wait(25)
                    sample['observations'] = server.observations or {'status': 'timeout'}
                    sample['probeSha256'] = hashlib.sha256(server.probe_source).hexdigest()
                actor = f'{args.driver_name} external-driver task'
                record_operator_outcome(sample, prompt_operator_outcome(actor), actor)
            except Exception as error:
                sample['error'] = str(error)
                attach_failed_captures(sample, server)
    return sample


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:18881')
    parser.add_argument('--browser-version', default=BROWSER_VERSION)
    parser.add_argument('--browsers', nargs='+', choices=['camoufox', 'firefox'], default=['camoufox', 'firefox'])
    parser.add_argument('--modes', nargs='+', choices=['form', 'invisible', 'widget'], default=['invisible', 'widget'])
    parser.add_argument('--display', choices=['both', 'headed', 'headless'], default='both')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=87)
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--out', type=Path, default=ROOT/'bench/test-results/camoufox')
    capture_mode = parser.add_mutually_exclusive_group()
    capture_mode.add_argument('--manual', action='store_true', help='Record one person using their own browser; launches no browser automation')
    capture_mode.add_argument('--accessibility-manual', action='store_true', help='Record one consented accessibility workflow with pinned tool provenance; launches no browser automation')
    capture_mode.add_argument('--external-agent', action='store_true', help='Record a browser-internal agent in an operator-opened browser; attaches no automation driver')
    capture_mode.add_argument('--external-driver', action='store_true', help='Record an operator-started external browser automation driver')
    parser.add_argument('--environment-label', help='Required with manual and external capture modes; describe the exact browser and environment')
    parser.add_argument('--agent-label', help='Required with --external-agent, e.g. Chrome Auto Browse (Gemini)')
    parser.add_argument('--driver-name', help='Required with --external-driver, e.g. browser-harness')
    parser.add_argument('--driver-version', help='Required with --external-driver, e.g. 0.1.13')
    parser.add_argument('--driver-commit', help='Required with --external-driver; full lowercase Git SHA')
    parser.add_argument('--manual-workflow', help='Required with --accessibility-manual; lowercase workflow slug')
    parser.add_argument('--input-tool-name', help='Required with --accessibility-manual; exact assistive/input tool name')
    parser.add_argument('--input-tool-version', help='Required with --accessibility-manual; exact tool or operating-system version')
    parser.add_argument('--input-tool-settings', help='Required with --accessibility-manual; relevant enabled settings')
    parser.add_argument('--form-fixture', choices=sorted(FORM_FIXTURES), default='basic', help='Recorder-only form fields for manual accessibility input testing')
    parser.add_argument('--consent-confirmed', action='store_true', help='Confirm the operator consented to this accessibility capture')
    parser.add_argument('--isolated-test-context', action='store_true', help='Confirm a fresh test context with no personal data, accounts, or saved credentials')
    parser.add_argument('--expected-client-version', help='Require the loopback server to serve this exact FCaptcha client version')
    parser.add_argument('--verdict-log', type=Path, help='Local server verdict log; joins diagnostics missing from /api/score responses')
    parser.add_argument('--observations', action='store_true', help='Collect research probes after scoring; never submitted to FCaptcha')
    parser.add_argument('--control-settings', nargs='+', choices=['default', 'privacy', 'reduced-motion', 'privacy-reduced-motion'],
                        default=['default', 'privacy'])
    parser.add_argument('--camoufox-config', type=Path, help='Optional local JSON config for a labeled robustness experiment')
    args = parser.parse_args()
    args.camoufox_config = json.loads(args.camoufox_config.read_text()) if args.camoufox_config else {}
    if not isinstance(args.camoufox_config, dict):
        parser.error('--camoufox-config must contain an object')
    args.server = args.server.rstrip('/')
    parsed = urllib.parse.urlsplit(args.server)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
        parser.error('--server must be a loopback HTTP test server')
    if args.repeats < 1 or args.timeout < 1:
        parser.error('--repeats and --timeout must be positive')
    external_capture = args.manual or args.accessibility_manual or args.external_agent or args.external_driver
    if external_capture and (not args.environment_label or len(args.modes) != 1):
        parser.error('--manual/--accessibility-manual/--external-agent/--external-driver requires --environment-label and exactly one --modes value')
    if args.accessibility_manual:
        try:
            accessibility_workflow(args)
        except ValueError as error:
            parser.error(str(error))
    elif any((args.manual_workflow, args.input_tool_name, args.input_tool_version,
              args.input_tool_settings, args.consent_confirmed,
              args.isolated_test_context, args.form_fixture != 'basic')):
        parser.error('accessibility workflow arguments require --accessibility-manual')
    if args.form_fixture != 'basic' and args.modes != ['form']:
        parser.error('autofill and credentials form fixtures require --modes form')
    if args.external_agent and not args.agent_label:
        parser.error('--external-agent requires --agent-label')
    if args.external_driver:
        if not all((args.driver_name, args.driver_version, args.driver_commit)):
            parser.error('--external-driver requires --driver-name, --driver-version and --driver-commit')
        if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', args.driver_name):
            parser.error('--driver-name must be a lowercase hyphenated slug')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', args.driver_version):
            parser.error('--driver-version must be semantic')
        if not re.fullmatch(r'[a-f0-9]{40}', args.driver_commit):
            parser.error('--driver-commit must be a full lowercase Git SHA')
    if external_capture and not args.expected_client_version:
        parser.error('--manual/--accessibility-manual/--external-agent/--external-driver requires --expected-client-version')
    if args.expected_client_version and not re.fullmatch(r'\d+\.\d+\.\d+', args.expected_client_version):
        parser.error('--expected-client-version must be a semantic version such as 1.51.4')
    args.secret = os.environ.get('FCAPTCHA_VERIFY_SECRET') or os.environ.get('FCAPTCHA_SECRET')
    if not args.secret:
        parser.error('Set FCAPTCHA_SECRET (or FCAPTCHA_VERIFY_SECRET) to validate issued tokens')
    if (args.out/'report.json').exists():
        parser.error('Output already exists; select a fresh --out directory')
    status, _, _ = request(args.server + '/health')
    if status != 200:
        parser.error('FCaptcha server is not healthy')
    cases = []
    for browser in args.browsers:
        for headless in ([False, True] if args.display == 'both' else [args.display == 'headless']):
            for variant in ([False, True] if browser == 'camoufox' else args.control_settings):
                for mode in args.modes:
                    for repeat in range(args.repeats):
                        cases.append({'browser': browser, 'headless': headless, 'mode': mode, 'repeat': repeat,
                                      'humanize': variant if browser == 'camoufox' else False,
                                      'privacy': browser == 'firefox' and 'privacy' in variant,
                                      'reducedMotion': browser == 'firefox' and 'reduced-motion' in variant})
    packages = {}
    for package in ['camoufox', 'playwright', 'browserforge']:
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            if not external_capture:
                raise
    report = {
        'schemaVersion': 1, 'startedAt': datetime.now(timezone.utc).isoformat(),
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'clientSha256': hashlib.sha256((ROOT/'client/fcaptcha.js').read_bytes()).hexdigest(),
        'expectedClientVersion': args.expected_client_version,
        'recorderSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'platform': platform.platform(), 'server': args.server,
        'camoufoxBuild': args.browser_version, 'camoufoxConfig': args.camoufox_config,
        'researchObservations': args.observations,
        'packages': packages,
        'limitations': ['All input is automated; no human false-positive rate is measured.',
                        'Loopback proxy isolates state per sample and removes transport fingerprinting.',
                        'Default Camoufox fingerprints vary per launch; observations apply to these captures.'],
        'samples': [],
    }
    if args.manual or args.accessibility_manual:
        report['camoufoxBuild'] = None
        report['limitations'] = ([
            'Browser configuration and manual input are operator-declared.',
            'A single-person capture is not a population false-positive estimate.',
            'Loopback proxy isolates state and removes transport fingerprinting.',
        ] + (['Accessibility tool, settings, consent, and test-context isolation are operator-declared.']
             if args.accessibility_manual else []))
        report['samples'] = [manual_capture(args)]
        report['summary'] = summarize(report['samples'])
        write_json(args.out/'report.json', report)
        print(f'Report: {args.out / "report.json"}', flush=True)
        return int('error' in report['samples'][0])
    if args.external_agent:
        report['camoufoxBuild'] = None
        report['limitations'] = [
            'Browser configuration and browser-internal agent identity are operator-declared.',
            'No external automation protocol is attached by this recorder.',
            'Loopback proxy isolates state and removes transport fingerprinting.',
            'One capture measures one session, not an agent population.',
        ]
        report['samples'] = [browser_internal_capture(args)]
        report['summary'] = summarize(report['samples'])
        write_json(args.out/'report.json', report)
        print(f'Report: {args.out / "report.json"}', flush=True)
        return int('error' in report['samples'][0])
    if args.external_driver:
        report['camoufoxBuild'] = None
        report['limitations'] = [
            'Browser configuration and external driver provenance are operator-declared.',
            'The recorder does not launch, install, or inspect the external driver.',
            'Loopback proxy isolates state and removes transport fingerprinting.',
            'One capture measures one session, not an agent population.',
        ]
        report['samples'] = [external_driver_capture(args)]
        report['summary'] = summarize(report['samples'])
        write_json(args.out/'report.json', report)
        print(f'Report: {args.out / "report.json"}', flush=True)
        return int('error' in report['samples'][0])
    for index, case in enumerate(cases):
        print(f'[{index+1}/{len(cases)}] {case}', flush=True)
        sample = run_case(args, case, index)
        report['samples'].append(sample)
        report['summary'] = summarize(report['samples'])
        write_json(args.out/'report.json', report)
        if 'error' in sample:
            print('  ERROR: ' + sample['error'], flush=True)
        else:
            capture = sample['capture']
            result = capture['response']
            print(f"  score={result['score']} validToken={capture['tokenValid']} experimental={result['experimental']['wouldBlock']}", flush=True)
    print(f'Report: {args.out / "report.json"}', flush=True)
    return int(any('error' in sample for sample in report['samples']))


if __name__ == '__main__':
    raise SystemExit(main())
