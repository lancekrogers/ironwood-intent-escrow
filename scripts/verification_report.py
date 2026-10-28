#!/usr/bin/env python3
"""Run the existing read-only verifier and publish a fail-closed JSON report."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TRANSACTIONS = ('fill.fund.tx', 'fill.spend.tx', 'refund.fund.tx', 'refund.spend.tx')
EXPECTED = {f'{tx} {suffix}' for tx in TRANSACTIONS for suffix in ('txid', 'fetched', 'check_zec')} | {
    'near payment recorded', 'near payment fetched', 'near payment attests',
    'refund address absent', 'policy outcomes recorded', 'broadcast sent',
}


def scope(name):
    if name.endswith(' fetched'):
        return 'network'
    if name in ('policy outcomes recorded', 'broadcast sent'):
        return 'recorded'
    return 'validation'


def parse_output(output, exit_code):
    checks = []
    seen = set()
    for line in output.splitlines():
        match = re.fullmatch(r'(PASS|FAIL|SKIP) (.+)', line)
        if not match:
            continue
        status, rest = match.groups()
        name, separator, detail = rest.partition(': ')
        if status == 'SKIP':
            name = name.removesuffix(' (offline)')
        if name not in EXPECTED or name in seen:
            raise ValueError(f'Unexpected or duplicate check: {name}')
        seen.add(name)
        checks.append({'name': name, 'status': status.lower(), 'detail': detail if separator else '', 'scope': scope(name)})
    if seen != EXPECTED:
        raise ValueError('Incomplete verifier output; not all 18 checks reported')
    summaries = re.findall(r'^(\d+) passed, (\d+) failed, (\d+) skipped \(offline\)$', output, re.M)
    actual = tuple(sum(c['status'] == status for c in checks) for status in ('pass', 'fail', 'skip'))
    if len(summaries) != 1 or tuple(map(int, summaries[0])) != actual:
        raise ValueError('Verifier summary does not match individual checks')
    # This adapter always invokes live mode. Skips or exit-code disagreement are errors.
    if actual[2] or (exit_code == 0) != (actual == (18, 0, 0)):
        raise ValueError('Verifier exit code or mode does not match its checks')
    return checks


def run_report(binary, timeout=180, run_url=None):
    started = time.monotonic()
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    report = {'schema_version': 1, 'mode': 'live', 'commit': commit, 'run_url': run_url,
              'status': 'unavailable', 'checks': [], 'error': None,
              'sources': {'zcash': 'https://testnet.zec.rocks:443', 'near': 'https://archival-rpc.testnet.near.org'}}
    try:
        process = subprocess.run([str(Path(binary).resolve())], cwd=ROOT, capture_output=True,
                                 text=True, timeout=timeout, check=False)
        report['checks'] = parse_output(process.stdout, process.returncode)
        report['status'] = 'passed' if process.returncode == 0 else 'failed'
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report['error'] = f'Verification could not complete: {type(error).__name__}'
    report['checked_at'] = datetime.now(timezone.utc).isoformat()
    report['duration_seconds'] = round(time.monotonic() - started, 2)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/verify')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-url')
    args = parser.parse_args()
    report = run_report(args.binary, run_url=args.run_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(args.output)
    print(f"Verification {report['status']}: {len(report['checks'])} checks; report written")
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
