import { AggregatorClient } from '../../../src/api/AggregatorClient.js';
import { BatchProofError } from '../../../src/api/BatchProofError.js';
import { isBatchAggregatorClient } from '../../../src/api/IBatchAggregatorClient.js';
import { StateId } from '../../../src/api/StateId.js';
import { DataHash } from '../../../src/crypto/hash/DataHash.js';
import { HashAlgorithm } from '../../../src/crypto/hash/HashAlgorithm.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { ShardedWorld } from '../../utils/ShardedWorld.js';

function stateId(fill: number): StateId {
  return StateId.fromCBOR(CborSerializer.encodeByteString(new Uint8Array(32).fill(fill)));
}

function respond(result: unknown, status = 200): jest.SpyInstance {
  return jest.spyOn(global, 'fetch').mockImplementation((_url, init) => {
    const id = (JSON.parse(init?.body as string) as { id: string }).id;
    return Promise.resolve(new Response(JSON.stringify({ id, jsonrpc: '2.0', ...(result as object) }), { status }));
  });
}

async function failure(promise: Promise<unknown>): Promise<BatchProofError> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(BatchProofError);
  return error as BatchProofError;
}

describe('AggregatorClient.getInclusionProofs', () => {
  const client = new AggregatorClient('https://example.com');
  afterEach(() => jest.restoreAllMocks());

  it('is an optional capability next to the unchanged required interface', () => {
    expect(isBatchAggregatorClient(client)).toBe(true);
    expect(isBatchAggregatorClient({ getInclusionProof: jest.fn(), submitCertificationRequest: jest.fn() })).toBe(
      false,
    );
  });

  it('sends the latest view by default and the exact root when given, with the signal', async () => {
    const world = await ShardedWorld.create(0);
    const batch = await world
      .client('')
      .getInclusionProofs([stateId(1)])
      .catch(() => null);
    expect(batch).toBeNull(); // a state nobody certified is not included: all or nothing

    const fetchMock = respond({ result: { proofs: [] } });
    const calls = fetchMock.mock.calls as [string, { body: string; signal: AbortSignal }][];
    const controller = new AbortController();
    await failure(client.getInclusionProofs([stateId(1)], { signal: controller.signal }));
    const body = JSON.parse(calls[0][1].body) as { method: string; params: unknown };
    expect(body.method).toEqual('get_inclusion_proofs.v1');
    expect(body.params).toEqual({ stateIds: [HexConverter.encode(new Uint8Array(32).fill(1))], stateRoot: 'latest' });
    expect(calls[0][1].signal).toBe(controller.signal);

    fetchMock.mockClear();
    await failure(
      client.getInclusionProofs([stateId(1), stateId(2)], {
        stateRoot: new DataHash(HashAlgorithm.SHA256, new Uint8Array(32).fill(9)),
      }),
    );
    const exact = JSON.parse((fetchMock.mock.calls as [string, { body: string }][])[0][1].body) as {
      params: { stateRoot: string };
    };
    expect(exact.params.stateRoot).toEqual('09'.repeat(32));
  });

  it('rejects a call outside the limits before any request', async () => {
    const fetchMock = jest.spyOn(global, 'fetch');
    expect((await failure(client.getInclusionProofs([]))).detail).toEqual('state_count');
    const many = Array.from({ length: 257 }, (_, i) => stateId(i % 250 === 0 ? 1 : 1)).map((_, i) =>
      StateId.fromCBOR(
        CborSerializer.encodeByteString(new Uint8Array(32).fill(0).map((_v, k) => (k === 0 ? i % 256 : i >> 8))),
      ),
    );
    expect((await failure(client.getInclusionProofs(many))).detail).toEqual('state_count');
    expect((await failure(client.getInclusionProofs([stateId(1), stateId(1)]))).detail).toEqual('duplicate_state_id');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['not an object', { result: 'zz' }],
    ['missing proofs', { result: {} }],
    ['wrong count', { result: { proofs: ['00', '00'] } }],
    ['proof not hex', { result: { proofs: ['zz'] } }],
    ['proof not a string', { result: { proofs: [1] } }],
    ['view for an exact root', { result: { partitionView: '00', proofs: [] } }],
  ])('classifies %s as an invalid response', async (name, response) => {
    respond(response);
    const exact = name === 'view for an exact root';
    const error = await failure(
      client.getInclusionProofs(
        [stateId(1)],
        exact ? { stateRoot: new DataHash(HashAlgorithm.SHA256, new Uint8Array(32)) } : undefined,
      ),
    );
    expect(error.kind).toEqual('invalid_response');
  });

  it.each([
    [
      -32008,
      { detail: 'view_not_retained', reason: 'proof_unavailable', retryable: true },
      'unavailable',
      'view_not_retained',
      true,
    ],
    [
      -32008,
      { detail: 'unsupported_configuration', reason: 'proof_unavailable', retryable: false },
      'unsupported',
      'unsupported_configuration',
      false,
    ],
    [-32006, { detail: 'pinned_views', reason: 'busy', retryable: true }, 'unavailable', 'busy:pinned_views', true],
    [-32006, undefined, 'unavailable', 'busy', true],
    [-32601, undefined, 'unsupported', 'method_not_found', false],
    [-32602, { detail: 'wrong_shard', reason: 'invalid_request' }, 'rejected', 'wrong_shard', false],
    [-32600, undefined, 'rejected', undefined, false],
    [-32007, { detail: 'response_bytes', reason: 'limit_exceeded' }, 'limit_exceeded', 'response_bytes', false],
    [-32004, undefined, 'server', undefined, false],
    [-32603, { reason: 'internal' }, 'server', undefined, false],
    [-1, undefined, 'server', undefined, false],
  ])('maps JSON-RPC error %i to a typed error', async (code, data, kind, detail, retryable) => {
    respond({ error: { code, data, message: 'x' } });
    const error = await failure(client.getInclusionProofs([stateId(1)]));
    expect(error.kind).toEqual(kind);
    expect(error.detail).toEqual(detail);
    expect(error.retryable).toEqual(retryable);
    expect(error.code).toEqual(code);
  });

  it('ignores unknown result fields (additive server fields) but keeps validating the known ones', async () => {
    const world = await ShardedWorld.create(0);
    const proof = Buffer.from((await world.client('').getInclusionProof(stateId(1))).toCBOR()).toString('hex');
    respond({ result: { extension: { nested: [1, 2] }, proofs: [proof], x: 'y' } });
    const batch = await client.getInclusionProofs([stateId(1)]);
    expect(batch.proofs).toHaveLength(1);
    expect(batch.partitionViewBytes).toBeNull();
    expect(Object.keys(batch)).not.toContain('extension');

    // known fields stay strict next to an unknown one
    jest.restoreAllMocks();
    respond({ result: { extra: 1, proofs: [proof, proof] } });
    expect((await failure(client.getInclusionProofs([stateId(1)]))).kind).toEqual('invalid_response');
    jest.restoreAllMocks();
    respond({ result: { extra: 1, partitionView: 5, proofs: [proof] } });
    expect((await failure(client.getInclusionProofs([stateId(1)]))).kind).toEqual('invalid_response');
  });

  it('sends the configured API key like submitCertificationRequest does', async () => {
    const keyed = new AggregatorClient('https://example.com', 'secret-key');
    const fetchMock = respond({ result: { proofs: [] } });
    await failure(keyed.getInclusionProofs([stateId(1)]));
    const init = (fetchMock.mock.calls as [string, { headers: Headers | Record<string, string> }][])[0][1];
    expect(new Headers(init.headers).get('X-API-Key')).toEqual('secret-key');

    fetchMock.mockClear();
    await failure(client.getInclusionProofs([stateId(1)]));
    const plain = (fetchMock.mock.calls as [string, { headers: Headers | Record<string, string> }][])[0][1];
    expect(new Headers(plain.headers).get('X-API-Key')).toBeNull();
  });

  it.each([401, 403])('classifies HTTP %i as a transport failure that is not retryable', async (status) => {
    jest.spyOn(global, 'fetch').mockResolvedValue(new Response('denied', { status }));
    const error = await failure(client.getInclusionProofs([stateId(1)]));
    expect(error.kind).toEqual('transport');
    expect(error.detail).toEqual(`http_${status}`);
    expect(error.retryable).toBe(false);
  });

  it('types transport failures and keeps cancellation as the platform error', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(new Response('down', { status: 503 }));
    const transport = await failure(client.getInclusionProofs([stateId(1)]));
    expect(transport.kind).toEqual('transport');
    expect(transport.retryable).toBe(true);

    jest.restoreAllMocks();
    jest.spyOn(global, 'fetch').mockRejectedValue(new TypeError('fetch failed'));
    expect((await failure(client.getInclusionProofs([stateId(1)]))).kind).toEqual('transport');

    jest.restoreAllMocks();
    const controller = new AbortController();
    jest.spyOn(global, 'fetch').mockImplementation(() => Promise.reject(new DOMException('aborted', 'AbortError')));
    controller.abort();
    await expect(client.getInclusionProofs([stateId(1)], { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
  });

  it('a gateway HTTP 400 for a batch across shards keeps the -32602 classification of the unchanged body', async () => {
    const fetchMock = respond(
      {
        error: {
          code: -32602,
          data: { detail: 'wrong_shard', reason: 'invalid_request', retryable: false },
          message: 'Invalid params',
        },
      },
      400,
    );
    const error = await failure(client.getInclusionProofs([stateId(1), stateId(2)], { waitMs: 5000 }));
    // read from the envelope behind the 400, as on HTTP 200: a rejected request, not a transport failure, and not the
    // malformed_params case, so there is no second request without waitMs
    expect(error.kind).toBe('rejected');
    expect(error.detail).toBe('wrong_shard');
    expect(error.retryable).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
