import test from 'node:test';
import assert from 'node:assert/strict';
import {boundedBody, fetchTransaction, ZCASH_SOURCE} from './upstream.mjs';

const txid = '01'.repeat(32);
function mock(raw = {}, detail = {}, network = 'testnet') {
  return async (url, init) => {
    assert.ok(url.startsWith(`${ZCASH_SOURCE}/v1/transactions/${txid}`));
    assert.equal(init.redirect, 'manual');
    assert.equal(init.cache, 'no-store');
    return Response.json({meta:{network}, data: url.endsWith('/raw')
      ? {txid, hex:'abcd', ...raw}
      : {txid, blockHeight:'4530559', status:'confirmed', isCanonical:true, ...detail}});
  };
}

test('fetches raw bytes and independently reported mined height', async () => {
  assert.deepEqual(await fetchTransaction(txid, mock()), {data:'abcd', height:4530559});
});

test('rejects different transactions, networks, malformed bytes, or unconfirmed records', async () => {
  for (const fetcher of [
    mock({txid:'02'.repeat(32)}), mock({}, {txid:'02'.repeat(32)}), mock({}, {}, 'mainnet'),
    mock({hex:'a'}), mock({hex:'zz'}), mock({hex:''}),
    mock({}, {isCanonical:false}), mock({}, {status:'pending'}),
    mock({}, {blockHeight:'0'}), mock({}, {blockHeight:'1x'}),
    mock({}, {blockHeight:'999999999999999999999'}),
  ]) await assert.rejects(fetchTransaction(txid, fetcher));
  await assert.rejects(fetchTransaction('../other', mock()));
});

test('HTTP errors and oversized upstream responses cannot become a pass', async () => {
  await assert.rejects(boundedBody(new Response('oversize'), 3));
  await assert.rejects(fetchTransaction(txid, async () => new Response('bad', {status:503})));
  await assert.rejects(fetchTransaction(txid, async () => new Response('not json')));
});
