import { JsonRpcDataError } from '../../../../src/api/json-rpc/JsonRpcDataError.js';
import { JsonRpcHttpTransport } from '../../../../src/api/json-rpc/JsonRpcHttpTransport.js';
import { JsonRpcNetworkError } from '../../../../src/api/json-rpc/JsonRpcNetworkError.js';
import { JsonRpcResponseError } from '../../../../src/api/json-rpc/JsonRpcResponseError.js';

describe('JsonRpcHttpTransport', () => {
  const transport = new JsonRpcHttpTransport('https://example.com');
  const fetchMock = jest.spyOn(global, 'fetch');

  afterEach(() => {
    fetchMock.mockReset();
  });

  afterAll(() => {
    fetchMock.mockRestore();
  });

  const respondWith = (payload: (id: unknown) => Record<string, unknown>, status = 200): void => {
    fetchMock.mockImplementation((_input, init) => {
      const id = (JSON.parse(init?.body as string) as { id: unknown }).id;
      return Promise.resolve(new Response(JSON.stringify(payload(id)), { status }));
    });
  };

  it('should return the result on a valid response', async () => {
    respondWith((id) => ({ id, jsonrpc: '2.0', result: 'ok' }));
    await expect(transport.request('m', {})).resolves.toBe('ok');
  });

  it('should reject an unsupported jsonrpc version', async () => {
    respondWith((id) => ({ id, jsonrpc: '1.0', result: 'ok' }));
    await expect(transport.request('m', {})).rejects.toThrow('Unsupported JSON-RPC version');
  });

  it('should reject a mismatched response id', async () => {
    respondWith(() => ({ id: 'other', jsonrpc: '2.0', result: 'ok' }));
    await expect(transport.request('m', {})).rejects.toThrow('id mismatch');
  });

  it('should reject a response with both result and error', async () => {
    respondWith((id) => ({ error: { code: 1, message: 'x' }, id, jsonrpc: '2.0', result: 'ok' }));
    await expect(transport.request('m', {})).rejects.toThrow('exactly one of result or error');
  });

  it('should reject a response with neither result nor error', async () => {
    respondWith((id) => ({ id, jsonrpc: '2.0' }));
    await expect(transport.request('m', {})).rejects.toThrow('exactly one of result or error');
  });

  it('should surface a JSON-RPC error object', async () => {
    respondWith((id) => ({ error: { code: -1, message: 'boom' }, id, jsonrpc: '2.0' }));
    await expect(transport.request('m', {})).rejects.toThrow('boom');
  });

  it('should forward the abort signal to fetch', async () => {
    respondWith((id) => ({ id, jsonrpc: '2.0', result: 'ok' }));
    const controller = new AbortController();

    await expect(transport.request('m', {}, new Headers(), { signal: controller.signal })).resolves.toBe('ok');
    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
  });

  it('should reject once the request is aborted', async () => {
    fetchMock.mockImplementation((_input, init) => {
      const { signal } = init ?? {};
      return new Promise<Response>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
      });
    });
    const controller = new AbortController();
    const request = transport.request('m', {}, new Headers(), { signal: controller.signal });
    controller.abort(new Error('aborted by caller'));

    await expect(request).rejects.toThrow('aborted by caller');
  });

  it('should decode a multi-byte UTF-8 character split across stream chunks', async () => {
    fetchMock.mockImplementation((_input, init) => {
      const id = (JSON.parse((init?.body as string) ?? '{}') as { id: unknown }).id;
      // '🎉' (U+1F389) is the 4-byte sequence F0 9F 8E 89.
      const bytes = new TextEncoder().encode(JSON.stringify({ id, jsonrpc: '2.0', result: '🎉' }));
      const splitAt = bytes.indexOf(0xf0) + 2; // mid-emoji: F0 9F | 8E 89
      const stream = new ReadableStream<Uint8Array>({
        start(controller: ReadableStreamDefaultController<Uint8Array>): void {
          controller.enqueue(bytes.slice(0, splitAt));
          controller.enqueue(bytes.slice(splitAt));
          controller.close();
        },
      });
      return Promise.resolve(new Response(stream));
    });

    await expect(transport.request('m', {})).resolves.toBe('🎉');
  });

  describe('Retry-After', () => {
    const answer = (status: number, retryAfter: string | null, error = { code: -32006, message: 'busy' }): void => {
      fetchMock.mockImplementation((_input, init) => {
        const id = (JSON.parse(init?.body as string) as { id: unknown }).id;
        const headers: Record<string, string> = retryAfter === null ? {} : { 'Retry-After': retryAfter };
        return Promise.resolve(new Response(JSON.stringify({ error, id, jsonrpc: '2.0' }), { headers, status }));
      });
    };
    const caught = (): Promise<unknown> => transport.request('m', {}).catch((e: unknown) => e);

    it.each([
      ['3', 3000],
      [' 7 ', 7000],
      ['0', 0],
      ['60', 60_000],
      ['61', 60_000],
      ['99999999999999999999999999', 60_000],
      ['9'.repeat(400), 60_000],
    ])('delta-seconds %j is %j ms on an HTTP error and on an HTTP-200 error', async (value, ms) => {
      answer(503, value);
      const network = await caught();
      expect(network).toBeInstanceOf(JsonRpcNetworkError);
      expect((network as JsonRpcNetworkError).retryAfterMs).toBe(ms);
      expect((network as JsonRpcNetworkError).rpcError?.retryAfterMs).toBe(ms);
      answer(200, value);
      const data = await caught();
      expect(data).toBeInstanceOf(JsonRpcDataError);
      expect((data as JsonRpcDataError).retryAfterMs).toBe(ms);
    });

    it.each(['', 'abc', '-1', '+5', '1.5', '1e3', '3 s'])('ignores %j', async (value) => {
      answer(429, value);
      expect(((await caught()) as JsonRpcNetworkError).retryAfterMs).toBeUndefined();
      answer(200, value);
      expect(((await caught()) as JsonRpcDataError).retryAfterMs).toBeUndefined();
    });

    it('is absent without the header', async () => {
      answer(503, null);
      expect(((await caught()) as JsonRpcNetworkError).retryAfterMs).toBeUndefined();
    });
  });

  describe('error answers by id', () => {
    const raw = (body: string): void => {
      fetchMock.mockImplementation(() => Promise.resolve(new Response(body, { status: 200 })));
    };

    it('the exact null-id concurrency answer is a JsonRpcDataError that did not match our id', async () => {
      raw('{"jsonrpc":"2.0","error":{"code":-32006,"message":"Concurrency limit exceeded"},"id":null}');
      const error = await transport.request('m', {}).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(JsonRpcDataError);
      expect((error as JsonRpcDataError).code).toBe(-32006);
      expect((error as JsonRpcDataError).idMatched).toBe(false);
    });

    it('a different non-null id is a protocol error, even for -32006', async () => {
      raw('{"jsonrpc":"2.0","error":{"code":-32006,"message":"busy"},"id":"someone-else"}');
      const error = await transport.request('m', {}).catch((e: unknown) => e);
      expect(error).not.toBeInstanceOf(JsonRpcDataError);
      expect((error as Error).message).toContain('id mismatch');
    });
  });

  describe('Retry-After HTTP-date and intermediary statuses', () => {
    const now = Date.parse('Sun, 06 Nov 1994 08:49:37 GMT');
    it('accepts the three HTTP-date forms, floored at 0 and capped at 60 s', () => {
      const parse = (v: string): number | undefined => JsonRpcHttpTransport.parseRetryAfter(v, now);
      expect(parse('Sun, 06 Nov 1994 08:49:47 GMT')).toBe(10_000);
      expect(parse('Sunday, 06-Nov-94 08:49:47 GMT')).toBe(10_000);
      expect(parse('Sun Nov  6 08:49:47 1994')).toBe(10_000);
      expect(parse('Sun, 06 Nov 1994 08:00:00 GMT')).toBe(0);
      expect(parse('Mon, 07 Nov 1994 08:49:37 GMT')).toBe(60_000);
      for (const junk of ['soon', 'Sun, 32 Nov 1994 08:49:37 GMT', 'Sun, 06 Nov 1994 08:49:37 PST', '+5', '1.5']) {
        expect(parse(junk)).toBeUndefined();
      }
    });

    it('a 502 with a non-JSON body is a network error with its status; an oversized one carries the status too', async () => {
      fetchMock.mockImplementation(() =>
        Promise.resolve(new Response('<html>bad gateway</html>', { headers: { 'Retry-After': '2' }, status: 502 })),
      );
      const error = await transport.request('m', {}).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(JsonRpcNetworkError);
      expect((error as JsonRpcNetworkError).status).toBe(502);
      expect((error as JsonRpcNetworkError).retryAfterMs).toBe(2000);

      const small = new JsonRpcHttpTransport('https://example.com', 16);
      fetchMock.mockImplementation(() =>
        Promise.resolve(new Response('x'.repeat(100), { headers: { 'Retry-After': '3' }, status: 504 })),
      );
      const big = await small.request('m', {}).catch((e: unknown) => e);
      expect(big).toBeInstanceOf(JsonRpcResponseError);
      expect((big as JsonRpcResponseError).status).toBe(504);
      expect((big as JsonRpcResponseError).retryAfterMs).toBe(3000);
    });
  });
});
