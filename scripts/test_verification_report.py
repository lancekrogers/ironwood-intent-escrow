import unittest
from verification_report import EXPECTED, parse_output


def output(failed=None):
    lines = [f"{'FAIL' if name == failed else 'PASS'} {name}" + (': upstream unavailable' if name == failed else '') for name in sorted(EXPECTED)]
    return '\n'.join(lines + [f'{17 if failed else 18} passed, {1 if failed else 0} failed, 0 skipped (offline)'])


class ReportTests(unittest.TestCase):
    def test_live_success_and_recorded_claims_are_distinguished(self):
        checks = parse_output(output(), 0)
        self.assertEqual(len(checks), 18)
        self.assertEqual(sum(c['scope'] == 'network' for c in checks), 5)
        self.assertEqual(sum(c['scope'] == 'recorded' for c in checks), 2)

    def test_node_failure_is_preserved(self):
        check = next(c for c in parse_output(output('near payment fetched'), 1) if c['name'] == 'near payment fetched')
        self.assertEqual(check['status'], 'fail')
        self.assertEqual(check['detail'], 'upstream unavailable')

    def test_truncated_or_duplicate_output_is_not_success(self):
        for text in (output().replace('PASS near payment fetched\n', ''), 'PASS near payment fetched\n' + output()):
            with self.assertRaises(ValueError):
                parse_output(text, 0)

    def test_exit_code_or_summary_disagreement_is_not_success(self):
        for text, code in ((output(), 1), (output('near payment fetched'), 0), (output().replace('18 passed', '19 passed'), 0)):
            with self.assertRaises(ValueError):
                parse_output(text, code)

    def test_offline_checks_are_not_live_success(self):
        text = output().replace('PASS near payment fetched', 'SKIP near payment fetched (offline)').replace('18 passed, 0 failed, 0 skipped', '17 passed, 0 failed, 1 skipped')
        with self.assertRaises(ValueError):
            parse_output(text, 0)


if __name__ == '__main__':
    unittest.main()
