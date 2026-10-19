import { allowInsecureTransportFor } from '../../e2e/E2EConfig.js';

describe('E2E config: plaintext API key transport', () => {
  it('allows http for local hostnames', () => {
    for (const url of [
      'http://localhost:3000',
      'http://127.0.0.1:8080/rpc',
      'http://[::1]:3000',
      'http://host.docker.internal:8080',
    ]) {
      expect(allowInsecureTransportFor(url, {})).toBe(true);
    }
  });

  it('refuses remote http unless explicitly opted in', () => {
    expect(allowInsecureTransportFor('http://gateway.example', {})).toBe(false);
    expect(allowInsecureTransportFor('http://gateway.example', { E2E_ALLOW_INSECURE: '0' })).toBe(false);
    expect(allowInsecureTransportFor('http://gateway.example', { E2E_ALLOW_INSECURE: '1' })).toBe(true);
  });

  it('is not fooled by a local name in the user info or the path', () => {
    expect(allowInsecureTransportFor('http://localhost:3000@gateway.example', {})).toBe(false);
    expect(allowInsecureTransportFor('http://gateway.example/localhost', {})).toBe(false);
    expect(allowInsecureTransportFor('http://localhost.gateway.example', {})).toBe(false);
  });

  it('never needs the opt-out for https', () => {
    expect(allowInsecureTransportFor('https://gateway.example', {})).toBe(false);
    expect(allowInsecureTransportFor('https://gateway.example', { E2E_ALLOW_INSECURE: '1' })).toBe(false);
    expect(allowInsecureTransportFor('https://localhost:3000', {})).toBe(false);
  });
});
