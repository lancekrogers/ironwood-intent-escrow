import test from 'node:test';
import assert from 'node:assert/strict';
import {EXPECTED,validateReport,summary,PARTS,combineReports} from './report.mjs';
function report() {
  return {schema_version:1,mode:'live',commit:'a'.repeat(40),status:'passed',checked_at:'2026-10-27T20:00:00Z',checks:EXPECTED.map(name=>({name,status:'pass',detail:'',scope:name.endsWith(' fetched')?'network':['policy outcomes recorded','broadcast sent'].includes(name)?'recorded':'validation'}))};
}
test('all 18 checks are required for success',()=>{
  assert.equal(validateReport(report()).status,'passed');
  const partial=report();partial.checks.pop();assert.throws(()=>validateReport(partial));
  const duplicate=report();duplicate.checks[1]=duplicate.checks[0];assert.throws(()=>validateReport(duplicate));
});
test('failed checks cannot be called passed',()=>{
  const r=report();r.checks[0].status='fail';assert.throws(()=>validateReport(r));
  r.status='failed';validateReport(r);assert.equal(summary(r,Date.parse(r.checked_at)).state,'failed');
});
test('recorded assertions cannot be presented as network confirmation',()=>{
  const r=report();r.checks.find(c=>c.name==='policy outcomes recorded').scope='network';assert.throws(()=>validateReport(r));
});
test('old and future reports are not presented as current success',()=>{
  const r=report();assert.equal(summary(r,Date.parse('2026-10-29T20:00:00Z')).state,'stale');
  assert.equal(summary(r,Date.parse('2026-10-26T20:00:00Z')).state,'unavailable');
});
test('offline, skipped and malformed reports are rejected',()=>{
  for(const patch of [{mode:'offline'},{schema_version:2},{checked_at:'invalid'},{commit:'branch-name'}])assert.throws(()=>validateReport({...report(),...patch}));
  const r=report();r.checks[0].status='skip';assert.throws(()=>validateReport(r));
});

function partialReports() {
  const full = report();
  return PARTS.map(part => ({...full,part,checks:full.checks.filter(check => part === 'near' ? EXPECTED.slice(12).includes(check.name) : check.name.startsWith(`${part} `))}));
}
test('combines all five parts and preserves failures', () => {
  const parts = partialReports();
  assert.equal(combineReports(parts).checks.length, 18);
  parts[0].status = 'failed'; parts[0].checks[0].status = 'fail';
  assert.equal(combineReports(parts).status, 'failed');
});
test('missing, duplicate, mixed revision, and incomplete parts never pass', () => {
  assert.throws(() => combineReports(partialReports().slice(1)));
  for (const change of [
    parts => parts[0] = parts[1],
    parts => parts[0].commit = 'b'.repeat(40),
    parts => parts[0].checks.pop(),
    parts => parts[0].status = 'unavailable',
    parts => parts[0].checks[0].status = 'fail',
  ]) {
    const parts = partialReports(); change(parts); assert.throws(() => combineReports(parts));
  }
});
