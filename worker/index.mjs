import {initSync, request_spec, verify_responses} from './pkg/ironwood_verifier_wasm.js';
import wasmModule from './pkg/ironwood_verifier_wasm_bg.wasm';
import {boundedBody, fetchTransaction, ZCASH_SOURCE} from './upstream.mjs';
import {commit} from './pkg/source.mjs';

// Rust prepares checks of immutable embedded transactions at module startup.
// All live network responses and reports remain local to each request.
initSync({module: wasmModule});
const spec = JSON.parse(request_spec());

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = {'content-type': 'application/json', 'cache-control': 'no-store', 'vary': 'Origin'};
    const origin = request.headers.get('origin');
    if (origin === env.ALLOWED_ORIGIN) headers['access-control-allow-origin'] = origin;
    const respond = (body, status = 200) => new Response(JSON.stringify(body), {status, headers});
    if (url.pathname === '/health' && request.method === 'GET') return respond({status: 'ok', commit});
    if (url.pathname !== '/api/verify' || url.search) return respond({error: 'Not found'}, 404);
    if (request.method !== 'GET') return respond({error: 'Method not allowed'}, 405);
    if (origin && origin !== env.ALLOWED_ORIGIN) return respond({error: 'Origin not allowed'}, 403);
    const {success} = await env.VERIFY_LIMIT.limit({key: request.headers.get('CF-Connecting-IP') || 'unknown'});
    if (!success) {
      headers['retry-after'] = '60';
      return respond({error: 'Please wait a minute before checking again.'}, 429);
    }
    const started = Date.now();
    const report = {schema_version: 1, mode: 'live', commit, run_url: null,
      status: 'unavailable', checks: [], error: null,
      sources: {zcash: ZCASH_SOURCE, near: spec.near_url}};
    try {
      const zcash = {};
      let near = new Uint8Array(), nearError = '';
      await Promise.all([
        ...spec.transactions.map(async tx => {
          try { zcash[tx.file] = await fetchTransaction(tx.txid); }
          catch (error) { zcash[tx.file] = {error: error.message}; }
        }),
        (async () => {
          try {
            const response = await fetch(spec.near_url, {
              method: 'POST', redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(20000),
              headers: {'content-type': 'application/json'},
              body: JSON.stringify({jsonrpc: '2.0', id: 'ironwood-intent-escrow', method: 'tx',
                params: {tx_hash: spec.near_hash, sender_account_id: spec.near_sender, wait_until: 'FINAL'}}),
            });
            if (!response.ok) {
              await response.body?.cancel();
              throw new Error(`NEAR RPC unavailable (HTTP ${response.status})`);
            }
            near = await boundedBody(response);
          } catch (error) { nearError = error.message; }
        })(),
      ]);
      Object.assign(report, JSON.parse(verify_responses(JSON.stringify(zcash), near, nearError)));
    } catch (error) {
      report.error = 'Verification could not complete.';
      console.error(JSON.stringify({event: 'verification_error', error: String(error)}));
    }
    report.checked_at = new Date().toISOString();
    report.duration_seconds = (Date.now() - started) / 1000;
    console.log(JSON.stringify({event: 'verification', status: report.status, duration_seconds: report.duration_seconds}));
    return respond(report);
  },
};
