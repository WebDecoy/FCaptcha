import copy
import unittest

from summarize_observations import animation_observation, observations, summarize_reports


def timing(finite_duration):
    cases = {}
    for kind in ['finite', 'repeated', 'infinite']:
        cases[kind] = {'specifiedDuration': 1000, 'samples': [
            {'duration': 1000 if kind == 'infinite' else finite_duration} for _ in range(4)]}
    return {'animation': {'status': 'ok', 'value': {'status': 'ok', 'tests': cases}}}


class ObservationTests(unittest.TestCase):
    def test_missing_and_unsupported_are_unknown(self):
        self.assertIsNone(animation_observation(None))
        self.assertIsNone(animation_observation({'animation': {'status': 'unsupported'}}))
        self.assertTrue(all(value is None for value in observations({}).values()))

    def test_requires_confirmation_in_both_document_contexts(self):
        sample = {'observations': {'revision': 'browser-consistency-v1', 'main': timing(0)}}
        self.assertIsNone(observations(sample)['animationTimingConflict'])
        sample['observations']['iframe'] = {'status': 'ok', 'value': timing(0)}
        self.assertTrue(observations(sample)['animationTimingConflict'])
        sample['observations']['iframe']['value'] = timing(1000)
        self.assertFalse(observations(sample)['animationTimingConflict'])

    def test_altered_requested_timing_is_not_the_candidate(self):
        value = timing(0)
        value['animation']['value']['tests']['finite']['specifiedDuration'] = 0
        self.assertIsNone(animation_observation(value))

    def test_unknowns_do_not_inflate_negative_control_counts(self):
        base = {'browser': 'control', 'headless': True, 'humanize': False, 'privacy': False}
        positive = {**base, 'observations': {'revision': 'browser-consistency-v1',
                    'main': timing(0), 'iframe': {'status': 'ok', 'value': timing(0)}}}
        negative = copy.deepcopy(positive)
        negative['observations']['main'] = timing(1000)
        missing = {**base, 'error': 'timeout'}
        result = summarize_reports([('test', {'samples': [positive, negative, missing]})])
        group = next(iter(result['groups'].values()))
        self.assertEqual(group['features']['animationTimingConflict'],
                         {'observed': 2, 'present': 1, 'unknown': 1})
        self.assertEqual(group['captureErrors'], 1)

    def test_unavailable_graphics_are_unknown(self):
        graphics = {'status': 'ok', 'value': {'status': 'ok', 'error': 1282,
                    'parameters': {}, 'pixel': [0, 0, 0, 0]}}
        realm = {'htmlWebgl': graphics, 'offscreenWebgl': graphics}
        sample = {'observations': {'revision': 'browser-consistency-v1', 'main': realm,
                  'iframe': {'status': 'ok', 'value': realm},
                  'worker': {'status': 'ok', 'value': realm}}}
        result = observations(sample)
        self.assertIsNone(result['graphicsReadbackDifference'])
        graphics['value']['error'] = 0
        self.assertFalse(observations(sample)['graphicsReadbackDifference'])
        self.assertIsNone(observations(sample)['advertisedExtensionUnavailable'])


if __name__ == '__main__':
    unittest.main()
