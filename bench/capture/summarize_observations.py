#!/usr/bin/env python3
"""Summarize research observations; findings are not detector verdicts."""
import argparse
import json
from pathlib import Path


def unwrap(value):
    return value.get('value') if isinstance(value, dict) and value.get('status') == 'ok' else None


def animation_observation(realm):
    if not isinstance(realm, dict):
        return None
    animation = unwrap(realm.get('animation'))
    if not animation or animation.get('status') != 'ok':
        return None
    values = {}
    for kind in ['finite', 'repeated', 'infinite']:
        case = animation.get('tests', {}).get(kind, {})
        points = case.get('samples', [])
        if case.get('specifiedDuration') != 1000 or len(points) != 4:
            return None
        durations = [point.get('duration') for point in points]
        if any(type(value) not in (int, float) for value in durations):
            return None
        values[kind] = durations
    return (all(value == 0 for value in values['finite'] + values['repeated'])
            and all(value == 1000 for value in values['infinite']))


def observations(sample):
    data = sample.get('observations', {})
    if data.get('revision') != 'browser-consistency-v1':
        return {'animationTimingConflict': None, 'graphicsParameterDifference': None,
                'graphicsReadbackDifference': None, 'advertisedExtensionUnavailable': None}
    main = data.get('main')
    frame = unwrap(data.get('iframe'))
    worker = unwrap(data.get('worker'))
    animation = [animation_observation(realm) for realm in [main, frame]]
    results = {'animationTimingConflict': None if None in animation else all(animation)}
    graphics = []
    for realm, key in [(main, 'htmlWebgl'), (main, 'offscreenWebgl'),
                       (frame, 'htmlWebgl'), (worker, 'offscreenWebgl')]:
        value = unwrap(realm.get(key)) if isinstance(realm, dict) else None
        if value and value.get('status') == 'ok' and value.get('error') == 0:
            graphics.append(value)
    if len(graphics) == 4:
        common = set.intersection(*(set(value['parameters']) for value in graphics))
        results['graphicsParameterDifference'] = any(
            len({json.dumps(value['parameters'][key], sort_keys=True) for value in graphics}) > 1 for key in common)
        results['graphicsReadbackDifference'] = len({json.dumps(value['pixel']) for value in graphics}) > 1
        extensions = [value.get('unavailableAdvertisedExtensions') for value in graphics]
        results['advertisedExtensionUnavailable'] = (any(extensions)
            if all(isinstance(value, list) for value in extensions) else None)
    else:
        results.update(graphicsParameterDifference=None, graphicsReadbackDifference=None, advertisedExtensionUnavailable=None)
    return results


def summarize_reports(reports):
    groups = {}
    samples = []
    for source, report in reports:
        for index, sample in enumerate(report['samples']):
            setting = '/'.join([sample['browser'], 'headless' if sample['headless'] else 'headed',
                                ('privacy' if sample.get('privacy') is True else 'default'
                                 if sample.get('privacy') is False else 'privacy-unknown'),
                                'reduced-motion' if sample.get('reducedMotion') else 'normal-motion',
                                'humanized' if sample.get('humanize') else 'standard-input',
                                json.dumps(report.get('camoufoxConfig', {}), sort_keys=True)])
            group = groups.setdefault(setting, {'attempts': 0, 'captureErrors': 0, 'features': {}})
            group['attempts'] += 1
            group['captureErrors'] += int('error' in sample)
            findings = observations(sample)
            for name, value in findings.items():
                feature = group['features'].setdefault(name, {'observed': 0, 'present': 0, 'unknown': 0})
                if value is None:
                    feature['unknown'] += 1
                else:
                    feature['observed'] += 1
                    feature['present'] += int(value)
            samples.append({'source': str(source), 'sampleIndex': index, 'setting': setting, 'observations': findings})
    return {'kind': 'research-observation-summary',
            'warning': 'No detection rates or human false-positive estimates. Unknowns are excluded from observed counts.',
            'groups': groups, 'samples': samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='+', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Output already exists')
    result = summarize_reports([(path, json.loads(path.read_text())) for path in args.reports])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    for name, group in result['groups'].items():
        print(name, json.dumps(group))


if __name__ == '__main__':
    main()
