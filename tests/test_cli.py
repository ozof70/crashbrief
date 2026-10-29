import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        # Keep test scratch under the caller-selected TMPDIR/TEMP or OS default.
        self.temp = tempfile.TemporaryDirectory(prefix='crashbrief-tests-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.env = {**os.environ, 'PYTHONPATH': str(root / 'src'), 'PYTHONIOENCODING': 'utf-8'}

    def run_cli(self, *args, data=b''):
        return subprocess.run([sys.executable, '-m', 'crashbrief', *map(str, args)],
                              input=data, capture_output=True, env=self.env, timeout=15)

    def test_stdin_to_json(self):
        result = self.run_cli('--format', 'json', data=b'ERROR password=private-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b'private-value', result.stdout)
        self.assertEqual(json.loads(result.stdout)['analysis']['error_lines'], 1)

    def test_output_file_and_no_overwrite(self):
        target = self.path / 'report.md'
        self.assertEqual(self.run_cli('-o', target, data=b'normal').returncode, 0)
        original = target.read_bytes()
        self.assertEqual(self.run_cli('-o', target, data=b'changed').returncode, 2)
        self.assertEqual(target.read_bytes(), original)

    def test_input_cannot_be_overwritten(self):
        source = self.path / 'source.txt'
        source.write_text('password=private-value', encoding='utf-8')
        self.assertEqual(self.run_cli(source, '-o', source).returncode, 2)
        self.assertEqual(source.read_text(), 'password=private-value')

    def test_multiple_inputs_do_not_reveal_filenames(self):
        paths = [self.path / 'private-name.txt', self.path / 'other-private.txt']
        for path in paths:
            path.write_text('ERROR boom', encoding='utf-8')
        result = self.run_cli(*paths, '--format', 'json')
        report = json.loads(result.stdout)
        self.assertEqual(report['analysis']['error_lines'], 2)
        self.assertIn('input 1', report['log'])
        self.assertNotIn('private-name', result.stdout.decode())

    def test_size_limit(self):
        result = self.run_cli(data=b'x' * (2*1024*1024+1))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)

    def test_combined_size_limit(self):
        source = self.path / 'large.txt'
        source.write_bytes(b'x' * (1024*1024+1))
        self.assertEqual(self.run_cli(source, source).returncode, 2)

    def test_invalid_utf8_does_not_echo_input(self):
        result = self.run_cli(data=b'private-raw\xff')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'private-raw', result.stderr)

    def test_missing_file_does_not_echo_path(self):
        result = self.run_cli(self.path / 'private-name.log')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'private-name', result.stderr)

    def test_redaction_gate_still_writes_report(self):
        result = self.run_cli('--fail-on-redaction', data=b'password=private-value')
        self.assertEqual(result.returncode, 3)
        self.assertIn(b'REDACTED', result.stdout)

    def test_error_gate(self):
        self.assertEqual(self.run_cli('--fail-on-error', data=b'ERROR boom').returncode, 4)
        self.assertEqual(self.run_cli('--fail-on-error', data=b'INFO done').returncode, 0)

    def test_config_custom_literals_and_title_override(self):
        config = self.path / 'config.toml'
        config.write_text('title="Config title"\nredact=["internal-host"]', encoding='utf-8')
        result = self.run_cli('--config', config, '--title', 'CLI title', data=b'internal-host')
        self.assertNotIn(b'internal-host', result.stdout)
        self.assertIn(b'# CLI title', result.stdout)

    def test_custom_literal_file(self):
        custom = self.path / 'literals.txt'
        custom.write_text('internal-host\n', encoding='utf-8')
        result = self.run_cli('--redact-file', custom, data=b'internal-host')
        self.assertNotIn(b'internal-host', result.stdout)

    def test_compare_cli(self):
        baseline = self.path / 'baseline.json'
        self.assertEqual(self.run_cli('--format', 'json', '-o', baseline, data=b'ECONNREFUSED').returncode, 0)
        result = self.run_cli('--compare', baseline, '--format', 'json', data=b'TimeoutError')
        self.assertEqual(json.loads(result.stdout)['comparison']['new_signals'], ['timeout'])

    def test_invalid_baseline_does_not_echo_raw_json(self):
        baseline = self.path / 'bad.json'
        baseline.write_text('private-secret-not-json', encoding='utf-8')
        result = self.run_cli('--compare', baseline)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'private-secret', result.stderr)

    def test_rules_and_version(self):
        self.assertIn('private_key', json.loads(self.run_cli('--rules').stdout)['rules'])
        self.assertIn(b'0.1.0', self.run_cli('--version').stdout)

    def test_too_many_inputs(self):
        self.assertEqual(self.run_cli(*(['-']*21)).returncode, 2)

    def test_invalid_title(self):
        self.assertEqual(self.run_cli('--title', '').returncode, 2)

    def test_utf8_bom(self):
        result = self.run_cli('--format', 'json', data=b'\xef\xbb\xbfERROR boom')
        self.assertEqual(json.loads(result.stdout)['log'], 'ERROR boom')


if __name__ == '__main__':
    unittest.main()
