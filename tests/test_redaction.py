import unittest

from crashbrief.redact import Redactor, normalize
from crashbrief.report import build_report, render


class RedactionTests(unittest.TestCase):
    def test_credential_formats(self):
        cases = [
            ('API_KEY=super-secret-value', 'super-secret-value'),
            ('password="a secret with spaces"', 'a secret with spaces'),
            ("client_secret='private-value'", 'private-value'),
            ('{"access_token": "private-value"}', 'private-value'),
            ('?token=private-value&query=public', 'private-value'),
            ('DATABASE_PASSWORD=private-value', 'private-value'),
            ('X-API-Key: private-value', 'private-value'),
            ('Authorization: Bearer private-value', 'private-value'),
            ('Proxy-Authorization: Basic dXNlcjpwYXNz', 'dXNlcjpwYXNz'),
            ('postgres://user:private-value@db.example/test', 'user:private-value'),
            ('https://user:private-value@api.example/path', 'user:private-value'),
            ('password="unterminated-secret', 'unterminated-secret'),
        ]
        for text, secret in cases:
            with self.subTest(text=text):
                result = Redactor().redact(text)
                self.assertNotIn(secret, result)
                self.assertIn('[REDACTED_', result)

    def test_known_tokens(self):
        for token in ['ghp_' + 'x'*36, 'github_pat_' + 'a'*60, 'sk-proj-' + 'a'*40,
                      'xoxb-' + '1'*30, 'AKIA' + 'A'*16, 'AIza' + 'a'*35,
                      'eyJabcde.abcdefgh.abcdefgh']:
            with self.subTest(prefix=token[:5]):
                self.assertNotIn(token, Redactor().redact('received ' + token))

    def test_private_key_multiline(self):
        text = 'before\n-----BEGIN RSA PRIVATE KEY-----\nABCDEF\nGHIJKL\n-----END RSA PRIVATE KEY-----\nafter'
        result = Redactor().redact(text)
        self.assertEqual(result, 'before\n[REDACTED_1]\nafter')

    def test_incomplete_private_key_redacts_to_end(self):
        self.assertEqual(Redactor().redact('-----BEGIN PRIVATE KEY-----\nsensitive'), '[REDACTED_1]')

    def test_cookies(self):
        result = Redactor().redact('Cookie: sid=secret; other=private\nSet-Cookie: id=hidden; Secure\nnormal')
        for value in ['secret', 'private', 'hidden']:
            self.assertNotIn(value, result)
        self.assertIn('normal', result)

    def test_email_and_home_paths(self):
        result = Redactor().redact('person@example.com /home/alice/project/a.py C:\\Users\\Bob\\project\\b.js /Users/carol/a.go')
        for value in ['person@example.com', 'alice', 'Bob', 'carol']:
            self.assertNotIn(value, result)
        self.assertIn('/project/a.py', result)

    def test_stable_placeholders_and_occurrence_counts(self):
        redactor = Redactor()
        self.assertEqual(redactor.redact('token=secret token=secret'), 'token=[REDACTED_1] token=[REDACTED_1]')
        self.assertEqual(redactor.counts['assignment'], 2)
        self.assertEqual(redactor.redact('token=other'), 'token=[REDACTED_2]')

    def test_repeat_redaction_preserves_placeholders(self):
        once = Redactor().redact('password=private-value')
        self.assertEqual(Redactor().redact(once), once)

    def test_custom_literal_does_not_leak_remainder_of_overlapping_secret(self):
        result = Redactor(('private',)).redact('password=private-value')
        self.assertEqual(result, 'password=[REDACTED_1]')
        self.assertNotIn('-value', result)

    def test_custom_literals_are_literal_not_regex(self):
        result = Redactor(('a.b',)).redact('a.b axb')
        self.assertEqual(result, '[REDACTED_1] axb')

    def test_control_only_literal_has_no_empty_matches(self):
        redactor = Redactor(('\x00',))
        self.assertEqual(redactor.redact('normal'), 'normal')
        self.assertEqual(dict(redactor.counts), {})

    def test_ansi_osc_and_bidi_normalization(self):
        raw = '\x1b[31mERROR\x1b[0m\r\n\x1b]8;;https://example.com\x07link\x1b]8;;\x07\u202esecret\x00'
        self.assertEqual(normalize(raw), 'ERROR\nlinksecret')

    def test_redaction_all_renderers_and_title(self):
        report = build_report('password=log-secret', title='token=title-secret')
        for format in ['markdown', 'html', 'json']:
            with self.subTest(format=format):
                output = render(report, format)
                self.assertNotIn('log-secret', output)
                self.assertNotIn('title-secret', output)

    def test_custom_rules_limits(self):
        with self.assertRaises(ValueError):
            Redactor(tuple(str(i) for i in range(101)))
        with self.assertRaises(ValueError):
            Redactor(('x'*4097,))

    def test_ordinary_text_is_not_secret(self):
        self.assertEqual(Redactor().redact('INFO request completed on port 8080'), 'INFO request completed on port 8080')

    def test_number_custom_literal_does_not_modify_inserted_placeholders(self):
        result = Redactor(('1',)).redact('1 password=secret')
        self.assertEqual(result, '[REDACTED_1] password=[REDACTED_2]')


if __name__ == '__main__':
    unittest.main()
