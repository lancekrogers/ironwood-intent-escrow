export const PARTS = ['fill.fund.tx', 'fill.spend.tx', 'refund.fund.tx', 'refund.spend.tx', 'near'];
export const EXPECTED = [
  ...['fill.fund.tx', 'fill.spend.tx', 'refund.fund.tx', 'refund.spend.tx'].flatMap(tx => ['txid', 'fetched', 'check_zec'].map(check => `${tx} ${check}`)),
  'near payment recorded', 'near payment fetched', 'near payment attests',
  'refund address absent', 'policy outcomes recorded', 'broadcast sent',
];
export function validateReport(report) {
  if (!report || report.schema_version !== 1 || report.mode !== 'live' || !['passed', 'failed', 'unavailable'].includes(report.status)) throw new Error('Unsupported verification report.');
  if (!/^[0-9a-f]{40}$/.test(report.commit) || !Number.isFinite(Date.parse(report.checked_at))) throw new Error('Report provenance is missing.');
  if (!Array.isArray(report.checks)) throw new Error('Missing checks.');
  if (report.status === 'unavailable' && report.checks.length === 0) return report;
  const names = new Set();
  for (const check of report.checks) {
    if (!EXPECTED.includes(check.name) || names.has(check.name) || !['pass', 'fail'].includes(check.status)) throw new Error('Incomplete or invalid verification results.');
    const expectedScope = check.name.endsWith(' fetched') ? 'network' : ['policy outcomes recorded', 'broadcast sent'].includes(check.name) ? 'recorded' : 'validation';
    if (check.scope !== expectedScope || typeof check.detail !== 'string') throw new Error('Invalid check classification.');
    names.add(check.name);
  }
  if (names.size !== EXPECTED.length || (report.status === 'passed') !== report.checks.every(check => check.status === 'pass')) throw new Error('Report summary disagrees with its checks.');
  return report;
}
export function freshness(report, now = Date.now()) {
  const age = now - Date.parse(report.checked_at);
  if (age < -300000) return 'future';
  return age > 24 * 60 * 60 * 1000 ? 'stale' : 'recent';
}
export function summary(report, now = Date.now()) {
  if (report.status === 'unavailable') return {state:'unavailable', title:'Verification unavailable', detail:report.error || 'The verifier did not complete. No successful result is claimed.'};
  const age = freshness(report, now);
  if (age === 'future') return {state:'unavailable', title:'Report time is invalid', detail:'The report is dated in the future. Do not treat it as a current check.'};
  if (report.status === 'failed') return {state:'failed', title:'Verification reported a failure', detail:'Inspect the failed checks below. A network error may mean a node is unavailable; it does not by itself establish invalid transactions.'};
  if (age === 'stale') return {state:'stale', title:'Saved verification is over 24 hours old', detail:'These checks passed at the time shown below. They are not a current confirmation of node availability.'};
  return {state:'passed', title:'18 checks passed', detail:'Five public testnet responses matched the recorded evidence. Validation checks and recorded signer outcomes are listed separately.'};
}

// Join only a complete set from the same deployed code revision. A missing part,
// failed HTTP request, or deployment changing mid-click cannot produce success.
export function combineReports(reports) {
  if (!Array.isArray(reports) || reports.length !== PARTS.length) throw new Error('Incomplete verification response.');
  const seen = new Set();
  const first = reports[0];
  for (const report of reports) {
    if (!report || !PARTS.includes(report.part) || seen.has(report.part) || report.commit !== first.commit || report.schema_version !== 1 || report.mode !== 'live' || !Number.isFinite(Date.parse(report.checked_at))) throw new Error('Verification parts disagree. Please retry.');
    if (!['passed','failed'].includes(report.status) || !Array.isArray(report.checks)) throw new Error('One verification request did not complete.');
    const names = report.part === 'near' ? EXPECTED.slice(12) : EXPECTED.filter(name => name.startsWith(`${report.part} `));
    if (report.checks.length !== names.length || report.checks.some(check => !names.includes(check.name)) || (report.status === 'passed') !== report.checks.every(check => check.status === 'pass')) throw new Error('Invalid partial verification results.');
    seen.add(report.part);
  }
  return validateReport({...first, part: undefined,
    checks: reports.flatMap(report => report.checks),
    status: reports.every(report => report.status === 'passed') ? 'passed' : 'failed',
    checked_at: new Date(Math.min(...reports.map(report => Date.parse(report.checked_at)))).toISOString(),
    duration_seconds: Math.max(...reports.map(report => report.duration_seconds || 0)),
  });
}
