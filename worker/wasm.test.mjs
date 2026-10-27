import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {initSync, request_spec, verify_responses} from './pkg/ironwood_verifier_wasm.js';
import {validateReport} from '../web/report.mjs';

initSync({module: readFileSync(new URL('./pkg/ironwood_verifier_wasm_bg.wasm', import.meta.url))});
// Match production startup: prepare immutable transaction checks before requests.
request_spec();
const read = name => readFileSync(new URL(`../runs/${name}`, import.meta.url));
function recordedResponses() {
  const fetched = {};
  for (const run of ['fill','refund']) {
    const record = JSON.parse(read(`${run}.json`));
    for (const step of ['fund','spend']) fetched[`${run}.${step}.tx`] = {
      data: read(`${run}.${step}.tx`).toString('hex'), height: record[`${step}_mined_height`],
    };
  }
  return fetched;
}
const verify = fetched => JSON.parse(verify_responses(JSON.stringify(fetched), read('fill.near.json'), ''));

test('actual Wasm produces the complete browser-compatible check set', () => {
  const report = verify(recordedResponses());
  assert.equal(report.status, 'passed');
  assert.equal(report.checks.length, 18);
  validateReport({...report, schema_version:1, mode:'live', commit:'a'.repeat(40), checked_at:new Date().toISOString(), error:null});
  assert.equal(JSON.parse(request_spec()).transactions.length, 4);
});

test('Wasm rejects a changed transaction and failed live requests', () => {
  const fetched = recordedResponses();
  fetched['fill.spend.tx'].data = readFileSync(new URL('../tests/fixtures/verify_bad/fill.spend.tx', import.meta.url)).toString('hex');
  fetched['refund.spend.tx'] = {error:'timeout'};
  const report = verify(fetched);
  assert.equal(report.status, 'failed');
  const failed = report.checks.filter(c => c.status === 'fail').map(c => c.name);
  assert.ok(failed.includes('fill.spend.tx fetched'));
  fetched['fill.spend.tx'].data = '00';
  assert.ok(verify(fetched).checks.some(c => c.name === 'fill.spend.tx check_zec' && c.status === 'fail'));
  assert.ok(failed.includes('refund.spend.tx fetched'));
  assert.ok(failed.includes('refund.spend.tx check_zec'));
  const absent = JSON.parse(verify_responses('{}', new Uint8Array(), 'NEAR unavailable'));
  assert.equal(absent.status, 'failed');
  assert.equal(absent.checks.filter(c => c.status === 'pass' && c.scope === 'network').length, 0);
});
