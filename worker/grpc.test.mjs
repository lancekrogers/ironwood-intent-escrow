import test from 'node:test';
import assert from 'node:assert/strict';
import {transactionRequest, decodeGrpcWeb, decodeRawTransaction, boundedBody, fetchTransaction} from './grpc.mjs';

function frame(flag, payload) {
  const bytes = new Uint8Array(5 + payload.length);
  bytes[0] = flag;
  new DataView(bytes.buffer).setUint32(1, payload.length);
  bytes.set(payload, 5);
  return bytes;
}
const raw = Uint8Array.of(10, 2, 0xab, 0xcd, 16, 150, 1);
const message = frame(0, raw);
const trailers = status => frame(128, new TextEncoder().encode(`grpc-status: ${status}\r\n`));
const response = status => new Uint8Array([...message, ...trailers(status)]);

test('encodes the lightwalletd transaction ID in wire byte order', () => {
  const txid = Array.from({length:32}, (_, i) => i.toString(16).padStart(2, '0')).join('');
  const bytes = transactionRequest(txid);
  assert.deepEqual([...bytes.slice(0, 7)], [0,0,0,0,34,26,32]);
  assert.deepEqual([...bytes.slice(7)], Array.from({length:32}, (_, i) => 31-i));
  assert.throws(() => transactionRequest('not a hash'));
});

test('requires a complete unary message and successful gRPC status', () => {
  assert.deepEqual(decodeGrpcWeb(response(0), new Headers()), {data:'abcd', height:150});
  for (const invalid of [message, response(7), response(0).slice(0,-1), new Uint8Array([...response(0),...message]), new Uint8Array([...message,...message,...trailers(0)]), frame(1, raw)]) {
    assert.throws(() => decodeGrpcWeb(invalid, new Headers()));
  }
  assert.throws(() => decodeGrpcWeb(response(0), new Headers({'grpc-status':'7'})));
});

test('rejects malformed, duplicate and overflowing protobuf fields', () => {
  for (const bytes of [Uint8Array.of(10,20,0), Uint8Array.of(10,1,0,16,0), new Uint8Array([...raw,16,1]), Uint8Array.of(10,1,0,16,...Array(10).fill(255)), Uint8Array.of(0)]) {
    assert.throws(() => decodeRawTransaction(bytes));
  }
});

test('bounds upstream bodies and refuses HTTP failures or wrong media types', async () => {
  await assert.rejects(boundedBody(new Response('oversize'), 3));
  const txid = '01'.repeat(32);
  await assert.rejects(fetchTransaction('https://example.test', txid, async () => new Response('bad', {status:415})));
  await assert.rejects(fetchTransaction('https://example.test', txid, async () => new Response('html')));
  const fetched = await fetchTransaction('https://example.test', txid, async (url, init) => {
    assert.equal(init.cf.grpcWeb, 'convert');
    assert.equal(init.redirect, 'manual');
    return new Response(response(0), {headers:{'content-type':'application/grpc-web+proto'}});
  });
  assert.deepEqual(fetched, {data:'abcd', height:150});
});
