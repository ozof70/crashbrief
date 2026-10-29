from dataclasses import asdict, replace
import hashlib
import json
import unittest

from crashbrief.analyze import analyze
from crashbrief.compare import compare_reports
from crashbrief.config import parse_config
from crashbrief.report import build_report, fence, render


class AnalysisTests(unittest.TestCase):
    def test_signatures_have_evidence_lines(self):
        result = analyze('INFO ready\nERROR ECONNREFUSED\nTimeoutError: timed out')
        self.assertEqual(result['error_lines'], 2)
        self.assertEqual(result['signals'][0]['lines'], [2])
        self.assertEqual(result['signals'][1]['code'], 'timeout')

    def test_timestamp_insensitive_error_grouping(self):
        result = analyze('2026-01-01T00:00:00Z ERROR down\n2026-01-01T00:00:01Z ERROR down')
        self.assertEqual(result['unique_error_lines'], 1)
        self.assertEqual(result['top_errors'], [{'text': 'ERROR down', 'count': 2}])

    def test_stack_frames(self):
        result = analyze('  File "app.py", line 42, in worker\n    at work (/app/index.js:12:7)')
        self.assertEqual(result['stack_frames'][0]['line'], 42)
        self.assertEqual(result['stack_frames'][1]['column'], 7)

    def test_stack_frame_limit(self):
        self.assertEqual(len(analyze('File "a.py", line 1\n'*30)['stack_frames']), 20)

    def test_oversized_frame_number_does_not_crash(self):
        self.assertEqual(analyze('File "a.py", line ' + '9'*5000)['stack_frames'], [])

    def test_unknown_error_is_not_diagnosed(self):
        result = analyze('ERROR something unexpected')
        self.assertEqual(result['signals'], [])
        self.assertEqual(result['error_lines'], 1)

    def test_all_builtin_signatures(self):
        signatures = {'ImportError': 'missing_dependency', 'EACCES': 'permission_denied',
                      'OOMKilled': 'out_of_memory', 'ENOSPC': 'disk_full', 'ENOTFOUND': 'dns_failure'}
        for text, expected in signatures.items():
            with self.subTest(text=text):
                self.assertEqual(analyze(text)['signals'][0]['code'], expected)


class RendererTests(unittest.TestCase):
    def test_empty_report(self):
        report = build_report('')
        self.assertEqual(report.analysis['line_count'], 0)
        for format in ['markdown', 'html', 'json']:
            self.assertTrue(render(report, format))

    def test_html_escapes_log_and_title(self):
        result = render(build_report('<script>alert(1)</script>', '<img src=x onerror=alert(1)>'), 'html')
        self.assertNotIn('<script>', result)
        self.assertNotIn('<img', result)
        self.assertIn('&lt;script&gt;', result)
        self.assertIn("default-src 'none'", result)

    def test_markdown_fence_cannot_be_closed_by_log(self):
        result = fence('```\n# malicious heading\n`````')
        self.assertTrue(result.startswith('``````text\n'))
        self.assertTrue(result.endswith('\n``````'))

    def test_markdown_title_is_escaped(self):
        result = render(build_report('normal', '[click](https://example.com)'), 'markdown')
        self.assertIn('\\[click\\]', result)

    def test_fingerprint_only_uses_redacted_content(self):
        report = build_report('token=private-value')
        self.assertEqual(report.fingerprint, hashlib.sha256(report.log.encode()).hexdigest())

    def test_json_contract(self):
        result = json.loads(render(build_report('你好 ERROR'), 'json'))
        self.assertEqual(result['schema_version'], 1)
        self.assertIn('你好', result['log'])
        self.assertNotIn('_values', str(result))

    def test_invalid_renderer(self):
        with self.assertRaises(ValueError):
            render(build_report(''), 'xml')


class CompareTests(unittest.TestCase):
    def test_signature_delta(self):
        old = asdict(build_report('ERROR ECONNREFUSED'))
        new = asdict(build_report('ERROR TimeoutError'))
        delta = compare_reports(new, old)
        self.assertEqual(delta['new_signals'], ['timeout'])
        self.assertEqual(delta['resolved_signals'], ['connection_refused'])

    def test_placeholder_numbers_do_not_create_differences(self):
        old = asdict(build_report('ERROR token=one'))
        new = asdict(build_report('person@example.com\nERROR token=two'))
        self.assertEqual(compare_reports(new, old)['increased_errors'], [])

    def test_untrusted_baseline_is_redacted_again(self):
        old = asdict(build_report('normal'))
        old['analysis']['top_errors'] = [{'text': 'ERROR password=baseline-secret', 'count': 1}]
        delta = compare_reports(asdict(build_report('normal')), old)
        self.assertNotIn('baseline-secret', json.dumps(delta))

    def test_bad_baseline_contract(self):
        for value in [[], {}, {'schema_version': 99}, {'schema_version': 1, 'analysis': []}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare_reports(asdict(build_report('')), value)

    def test_bad_count(self):
        old = asdict(build_report('ERROR boom'))
        old['analysis']['top_errors'][0]['count'] = True
        with self.assertRaises(ValueError):
            compare_reports(asdict(build_report('')), old)

    def test_unknown_baseline_signal_rejected(self):
        old = asdict(build_report('normal'))
        old['analysis']['signals'] = [{'code': 'untrusted_secret'}]
        with self.assertRaises(ValueError):
            compare_reports(asdict(build_report('')), old)

    def test_baseline_uses_custom_redaction_policy(self):
        old = asdict(build_report('ERROR internal-host'))
        delta = compare_reports(asdict(build_report('')), old, ('internal-host',))
        self.assertNotIn('internal-host', json.dumps(delta))

    def test_comparison_in_every_format(self):
        current = build_report('TimeoutError')
        delta = compare_reports(asdict(current), asdict(build_report('')))
        for format in ['markdown', 'html', 'json']:
            self.assertIn('timeout', render(replace(current, comparison=delta), format))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(parse_config(b'').title, 'Debugging report')

    def test_valid_config(self):
        config = parse_config(b'title="Checkout failure"\nredact=["internal-host"]')
        self.assertEqual(config.literals, ('internal-host',))

    def test_invalid_configs(self):
        for value in [b'bad TOML', b'title=1', b'redact="secret"', b'redact=[1]',
                      b'redact=[""]', b'title=""', b'unknown=true']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_config(value)
