#!/usr/bin/env python3
"""Collect research observations in an unmodified Firefox binary, without a driver.

This is a probe-only control. It does not measure CAPTCHA acceptance or human
interaction. A fresh temporary profile is used for each requested setting.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

from camoufox_bench import CaptureHandler, capture_server, write_json


class NativeHandler(CaptureHandler):
    def do_GET(self):
        if self.path != '/':
            return super().do_GET()
        # This separate probe-only page has no scoring request. The explicit
        # readiness flag permits saving observations to the local recorder.
        self.server.finished.set()
        self.respond(200, 'text/html', b'''<!doctype html><body>
<script src="/__research/probe.js"></script><script>
collectBrowserObservations().then(value => fetch('/__research/observations', {
  method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(value)
}));
</script>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--timeout', type=int, default=45)
    parser.add_argument('--settings', nargs='+', choices=['default', 'privacy', 'reduced-motion', 'privacy-reduced-motion'],
                        default=['default', 'privacy', 'reduced-motion', 'privacy-reduced-motion'])
    args = parser.parse_args()
    if not args.browser.is_file() or args.repeats < 1 or args.timeout < 1:
        parser.error('Provide an existing Firefox executable and positive repeats/timeout')
    if (args.out/'report.json').exists():
        parser.error('Output already exists')
    browser_version = subprocess.check_output([str(args.browser), '--version'], text=True).strip()
    report = {'schemaVersion': 1, 'kind': 'native-probe-control',
              'startedAt': datetime.now(timezone.utc).isoformat(), 'browserVersion': browser_version,
              'limitations': ['Headless API control with no driver. No human input or CAPTCHA verdict.',
                              'Temporary profiles, local page, one machine.'], 'samples': []}
    args.out.mkdir(parents=True, exist_ok=True)
    for setting in args.settings:
        for repeat in range(args.repeats):
            sample = {'browser': 'firefox-native', 'browserVersion': browser_version, 'headless': True,
                      'mode': 'probe-only', 'humanize': False, 'privacy': 'privacy' in setting,
                      'reducedMotion': 'reduced-motion' in setting, 'repeat': repeat, 'label': 'automated-control'}
            with capture_server('', 'probe-only', observations=True) as (server, url), tempfile.TemporaryDirectory() as profile:
                server.RequestHandlerClass = NativeHandler
                prefs = {'browser.shell.checkDefaultBrowser': False, 'app.update.auto': False,
                         'browser.startup.homepage_override.mstone': 'ignore',
                         'privacy.resistFingerprinting': sample['privacy']}
                if sample['reducedMotion']:
                    prefs['ui.prefersReducedMotion'] = 1
                Path(profile, 'user.js').write_text('\n'.join(
                    f'user_pref({json.dumps(key)}, {json.dumps(value)});' for key, value in prefs.items()))
                with (args.out/f'{setting}-{repeat}.log').open('w') as log:
                    process = subprocess.Popen([str(args.browser), '--headless', '--no-remote',
                                                '--profile', profile, url], stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                    try:
                        if not server.observations_finished.wait(args.timeout):
                            sample['error'] = 'No observation result; not a detection outcome'
                        else:
                            sample['observations'] = server.observations
                            sample['probeSha256'] = hashlib.sha256(server.probe_source).hexdigest()
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait()
            report['samples'].append(sample)
            write_json(args.out/'report.json', report)
            print(setting, repeat, sample.get('error', 'observations saved'), flush=True)
    return int(any('error' in sample for sample in report['samples']))


if __name__ == '__main__':
    raise SystemExit(main())
