// Unary GetTransaction only. Field numbers come from lightwalletd's service.proto:
// TxFilter.hash = 3; RawTransaction.data = 1, height = 2.
export function transactionRequest(txid) {
  if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error('Invalid recorded transaction ID');
  const request = new Uint8Array(39);
  request[4] = 34;
  request[5] = 0x1a;
  request[6] = 32;
  request.set(Uint8Array.from(txid.match(/../g), byte => parseInt(byte, 16)).reverse(), 7);
  return request;
}

export function decodeRawTransaction(bytes) {
  let offset = 0;
  function varint() {
    let value = 0n;
    for (let i = 0; i < 10 && offset < bytes.length; i++) {
      const byte = bytes[offset++];
      if (i === 9 && byte > 1) throw new Error('Protobuf integer overflow');
      value |= BigInt(byte & 127) << BigInt(7 * i);
      if (!(byte & 128)) return value;
    }
    throw new Error('Truncated protobuf integer');
  }
  function take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.length) throw new Error('Truncated protobuf field');
    const value = bytes.subarray(offset, offset + length);
    offset += length;
    return value;
  }
  let data;
  let height;
  while (offset < bytes.length) {
    const tag = varint();
    const field = Number(tag >> 3n), wire = Number(tag & 7n);
    if (field === 0) throw new Error('Invalid protobuf field');
    if (field === 1 && wire === 2 && data === undefined) data = take(Number(varint()));
    else if (field === 2 && wire === 0 && height === undefined) height = varint();
    else if (field === 1 || field === 2) throw new Error('Invalid or duplicate transaction field');
    else if (wire === 0) varint();
    else if (wire === 1) take(8);
    else if (wire === 2) take(Number(varint()));
    else if (wire === 5) take(4);
    else throw new Error('Unsupported protobuf field');
  }
  if (!data?.length || height === undefined || height === 0n || height > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('Response has no transaction or valid mined height');
  }
  return {data: Array.from(data, byte => byte.toString(16).padStart(2, '0')).join(''), height: Number(height)};
}

export function decodeGrpcWeb(bytes, headers) {
  let offset = 0, message, status = headers.get('grpc-status'), trailersSeen = false;
  while (offset < bytes.length) {
    if (bytes.length - offset < 5) throw new Error('Truncated gRPC frame');
    const flag = bytes[offset];
    const length = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 4).getUint32(0);
    offset += 5;
    if (length > bytes.length - offset || trailersSeen) throw new Error('Invalid gRPC frame length or order');
    const payload = bytes.subarray(offset, offset + length);
    offset += length;
    if (flag === 0 && message === undefined) message = payload;
    else if (flag === 128) {
      trailersSeen = true;
      const statuses = [...new TextDecoder('utf-8', {fatal: true}).decode(payload).matchAll(/^grpc-status:\s*(\d+)\s*$/gmi)];
      if (statuses.length !== 1 || (status !== null && status !== statuses[0][1])) throw new Error('Missing or inconsistent gRPC status');
      status = statuses[0][1];
    } else throw new Error('Unsupported compression or multiple gRPC messages');
  }
  if (status !== '0' || !message) throw new Error(`gRPC failed or status missing (${status ?? 'missing'})`);
  return decodeRawTransaction(message);
}

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

export async function fetchTransaction(url, txid, fetcher = fetch) {
  const response = await fetcher(`${url}/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction`, {
    method: 'POST', redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(20000),
    headers: {'content-type': 'application/grpc-web+proto', 'x-grpc-web': '1', 'grpc-timeout': '20S'},
    body: transactionRequest(txid),
    // Supported by workerd's RequestInitCfProperties; availability must be
    // verified on the target account. This does not silently fall back to records.
    cf: {grpcWeb: 'convert'},
  });
  if (!response.ok || !response.headers.get('content-type')?.startsWith('application/grpc-web')) {
    await response.body?.cancel();
    throw new Error(`Zcash gRPC transport unavailable (HTTP ${response.status})`);
  }
  return decodeGrpcWeb(await boundedBody(response), response.headers);
}
