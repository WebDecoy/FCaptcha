import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from camoufox_bench import attach_verdict_log, finish_capture, summarize


def sample():
    return {'browser': 'camoufox', 'headless': True, 'humanize': False,
            'privacy': False, 'mode': 'invisible', 'capture': {
                'tokenValid': True,
                'request': {'siteKey': 'sample-site'},
                'response': {'success': True, 'score': 0.1,
                             'experimental': {'mode': 'observe', 'wouldBlock': False}},
            }}


class MeasurementTests(unittest.TestCase):
    def test_errors_are_not_counted_as_detection_outcomes(self):
        allowed = sample()
        blocked = copy.deepcopy(allowed)
        blocked['capture']['tokenValid'] = None
        blocked['capture']['response'].update(success=False, score=0.9)
        failed = {**copy.deepcopy(blocked), 'error': 'proof failed'}
        group = next(iter(summarize([allowed, blocked, failed]).values()))
        self.assertEqual((group['attempts'], group['completed'], group['errors']), (3, 2, 1))
        self.assertEqual(group['validTokens'], 1)
        self.assertEqual(group['scores'], [0.1, 0.9])

    def test_baseline_blocks_are_not_counted_as_additional_experimental_blocks(self):
        baseline = sample()
        baseline['capture']['response']['score'] = 0.6
        baseline['capture']['response']['experimental']['wouldBlock'] = True
        candidate = sample()
        candidate['capture']['response']['experimental']['wouldBlock'] = True
        group = next(iter(summarize([baseline, candidate]).values()))
        self.assertEqual(group['experimentalWouldBlock'], 2)
        self.assertEqual(group['additionalExperimentalBlocks'], 1)

    def test_secret_stays_backend_only_and_saved_token_is_removed(self):
        record = sample()['capture']
        record.update(httpStatus=200)
        record['response']['token'] = 'issued-token'
        server = SimpleNamespace(records=[record], backend='http://127.0.0.1:3000', client_ip='192.0.2.1')
        with patch('camoufox_bench.request', return_value=(200, {}, b'{"valid":true}')) as send:
            captured = finish_capture(server, 'private-test-secret')
        self.assertTrue(captured['tokenValid'])
        self.assertEqual(send.call_args.args[1]['secret'], 'private-test-secret')
        self.assertNotIn('issued-token', json.dumps(captured))
        self.assertNotIn('private-test-secret', json.dumps(captured))

    def test_rejected_token_is_an_error_not_a_successful_measurement(self):
        record = sample()['capture']
        record.update(httpStatus=200)
        record['response']['token'] = 'invalid-token'
        server = SimpleNamespace(records=[record], backend='http://127.0.0.1:3000', client_ip='192.0.2.1')
        with patch('camoufox_bench.request', return_value=(200, {}, b'{"valid":false}')):
            with self.assertRaisesRegex(RuntimeError, 'valid token'):
                finish_capture(server, 'test-secret')
        self.assertNotIn('token', record['response'])

    def test_log_diagnostics_are_joined_by_sample_not_position(self):
        captured = sample()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'server.log'
            path.write_text('Server started\n' + '\n'.join(json.dumps(entry) for entry in [
                {'event': 'verdict', 'siteKey': 'other', 'score': 0.9},
                {'event': 'verdict', 'siteKey': 'sample-site', 'score': 0.1,
                 'detections': [{'category': 'automation', 'score': 0.5, 'confidence': 0.4}]},
            ]))
            attach_verdict_log(captured, path)
        self.assertEqual(captured['capture']['verdictLog']['score'], 0.1)
        group = next(iter(summarize([captured]).values()))
        self.assertEqual(len(group['detections']), 1)


if __name__ == '__main__':
    unittest.main()
