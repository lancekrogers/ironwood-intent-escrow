export async function boundedBody(response, limit = 1024 * 1024) {
  if (!response.body) throw new Error('Empty upstream response');
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      length += value.length;
      if (length > limit) throw new Error('Upstream response exceeds size limit');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}


// ZecBlock's public v1 API, documented in Kenbak/zecblock/public/openapi-v1.json.
export const ZCASH_SOURCE = 'https://api.testnet.zecblock.com';

async function api(path, fetcher) {
  const response = await fetcher(`${ZCASH_SOURCE}/v1/transactions/${path}`, {
    redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(20000),
    headers: {'accept': 'application/json'},
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Zcash API unavailable (HTTP ${response.status})`);
  }
  const json = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(await boundedBody(response)));
  if (json.meta?.network !== 'testnet' || !json.data) throw new Error('Zcash API returned no testnet data');
  return json.data;
}

export async function fetchTransaction(txid, fetcher = fetch) {
  if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error('Invalid recorded transaction ID');
  const [raw, detail] = await Promise.all([api(`${txid}/raw`, fetcher), api(txid, fetcher)]);
  if (raw.txid !== txid || detail.txid !== txid) throw new Error('Zcash API returned a different transaction');
  if (typeof raw.hex !== 'string' || !/^(?:[0-9a-fA-F]{2})+$/.test(raw.hex)) throw new Error('Zcash API returned invalid transaction bytes');
  if (detail.status !== 'confirmed' || detail.isCanonical !== true) throw new Error('Transaction is not confirmed on the canonical chain');
  const height = typeof detail.blockHeight === 'string' && /^[0-9]+$/.test(detail.blockHeight) ? Number(detail.blockHeight) : detail.blockHeight;
  if (!Number.isSafeInteger(height) || height <= 0) throw new Error('Zcash API returned an invalid mined height');
  return {data: raw.hex, height};
}
