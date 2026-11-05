import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { CborDeserializer } from '../../../../../src/serialization/cbor/CborDeserializer.js';
import { CborMap } from '../../../../../src/serialization/cbor/CborMap.js';
import { CborMapEntry } from '../../../../../src/serialization/cbor/CborMapEntry.js';
import { CborSerializer } from '../../../../../src/serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

/**
 * The shared V2 trust-base vectors, vendored byte for byte from ristik/bft-go-base, branch utb/upstream-v2, commit c202b48,
 * testdata/trust-base-v2/v1/vectors.json (see tests/vectors/trust-base-v2/README.md).
 */
export interface ITrustBaseVectors {
  readonly bundles: { readonly entryIds: string[]; readonly hex: string; readonly name: string }[];
  readonly decode: {
    readonly errorClass?: string;
    readonly hex: string;
    readonly name: string;
    readonly valid: boolean;
  }[];
  readonly entries: {
    readonly entryId: string;
    readonly hex: string;
    readonly name: string;
    readonly sigBytes: string;
  }[];
}

export function loadVectors(): ITrustBaseVectors {
  return JSON.parse(
    readFileSync(join(process.cwd(), 'tests/vectors/trust-base-v2/vectors.json'), 'utf8'),
  ) as ITrustBaseVectors;
}

export function vectorEntry(name: string): Uint8Array {
  const entry = loadVectors().entries.find((candidate) => candidate.name === name);
  if (!entry) {
    throw new Error(`No vector entry ${name}`);
  }
  return HexConverter.decode(entry.hex);
}

/**
 * The fields of an entry, parsed here at the raw CBOR level and independent of the class under test, so a test can change exactly one field.
 */
export interface IEntryFields {
  changeRecordHash: Uint8Array | null;
  epoch: bigint;
  epochStart: bigint;
  members: [string, Uint8Array, bigint][];
  network: bigint;
  previousEntryId: Uint8Array;
  quorum: bigint;
  signatures: [string, Uint8Array][] | null;
  stateHash: Uint8Array | null;
  version: bigint;
}

export function parseEntryFields(bytes: Uint8Array): IEntryFields {
  const f = CborDeserializer.decodeArray(CborDeserializer.decodeTag(bytes).data, 10);
  const hash = (data: Uint8Array): Uint8Array | null =>
    CborDeserializer.decodeNullable(data, (x) => CborDeserializer.decodeByteString(x));
  return {
    changeRecordHash: hash(f[7]),
    epoch: CborDeserializer.decodeUnsignedInteger(f[2]),
    epochStart: CborDeserializer.decodeUnsignedInteger(f[3]),
    members: CborDeserializer.decodeArray(f[4]).map((m): [string, Uint8Array, bigint] => {
      const x = CborDeserializer.decodeArray(m, 3);
      return [
        CborDeserializer.decodeTextString(x[0]),
        CborDeserializer.decodeByteString(x[1]),
        CborDeserializer.decodeUnsignedInteger(x[2]),
      ];
    }),
    network: CborDeserializer.decodeUnsignedInteger(f[1]),
    previousEntryId: CborDeserializer.decodeByteString(f[8]),
    quorum: CborDeserializer.decodeUnsignedInteger(f[5]),
    signatures: CborDeserializer.decodeNullable(f[9], (x) =>
      CborDeserializer.decodeMap(x).map((e): [string, Uint8Array] => [
        CborDeserializer.decodeTextString(e.key),
        CborDeserializer.decodeByteString(e.value),
      ]),
    ),
    stateHash: hash(f[6]),
    version: CborDeserializer.decodeUnsignedInteger(f[0]),
  };
}

export function buildEntry(f: IEntryFields): Uint8Array {
  const hash = (h: Uint8Array | null): Uint8Array =>
    h === null ? CborSerializer.encodeNull() : CborSerializer.encodeByteString(h);
  return CborSerializer.encodeTag(
    39000n,
    CborSerializer.encodeArray(
      CborSerializer.encodeUnsignedInteger(f.version),
      CborSerializer.encodeUnsignedInteger(f.network),
      CborSerializer.encodeUnsignedInteger(f.epoch),
      CborSerializer.encodeUnsignedInteger(f.epochStart),
      CborSerializer.encodeArray(
        ...f.members.map(([id, key, weight]) =>
          CborSerializer.encodeArray(
            CborSerializer.encodeTextString(id),
            CborSerializer.encodeByteString(key),
            CborSerializer.encodeUnsignedInteger(weight),
          ),
        ),
      ),
      CborSerializer.encodeUnsignedInteger(f.quorum),
      hash(f.stateHash),
      hash(f.changeRecordHash),
      CborSerializer.encodeByteString(f.previousEntryId),
      f.signatures === null
        ? CborSerializer.encodeNull()
        : CborSerializer.encodeMap(
            new CborMap(
              f.signatures.map(
                ([id, signature]) =>
                  new CborMapEntry(CborSerializer.encodeTextString(id), CborSerializer.encodeByteString(signature)),
              ),
            ),
          ),
    ),
  );
}

/**
 * A bundle header around entries embedded verbatim.
 */
export interface IBundleFields {
  effectiveEnd: bigint;
  endEntryId: Uint8Array | null;
  entries: Uint8Array[];
  fromEpoch: bigint;
  network: bigint;
  nextEpoch: bigint | null;
  status: bigint;
  version: bigint;
}

export function parseBundleFields(bytes: Uint8Array): IBundleFields {
  const f = CborDeserializer.decodeArray(CborDeserializer.decodeTag(bytes).data, 8);
  return {
    effectiveEnd: CborDeserializer.decodeUnsignedInteger(f[4]),
    endEntryId: CborDeserializer.decodeNullable(f[5], (x) => CborDeserializer.decodeByteString(x)),
    entries: CborDeserializer.decodeArray(f[6]),
    fromEpoch: CborDeserializer.decodeUnsignedInteger(f[3]),
    network: CborDeserializer.decodeUnsignedInteger(f[1]),
    nextEpoch: CborDeserializer.decodeNullable(f[7], (x) => CborDeserializer.decodeUnsignedInteger(x)),
    status: CborDeserializer.decodeUnsignedInteger(f[2]),
    version: CborDeserializer.decodeUnsignedInteger(f[0]),
  };
}

export function buildBundle(f: IBundleFields): Uint8Array {
  return CborSerializer.encodeTag(
    39015n,
    CborSerializer.encodeArray(
      CborSerializer.encodeUnsignedInteger(f.version),
      CborSerializer.encodeUnsignedInteger(f.network),
      CborSerializer.encodeUnsignedInteger(f.status),
      CborSerializer.encodeUnsignedInteger(f.fromEpoch),
      CborSerializer.encodeUnsignedInteger(f.effectiveEnd),
      f.endEntryId === null ? CborSerializer.encodeNull() : CborSerializer.encodeByteString(f.endEntryId),
      CborSerializer.encodeArray(...f.entries),
      f.nextEpoch === null ? CborSerializer.encodeNull() : CborSerializer.encodeUnsignedInteger(f.nextEpoch),
    ),
  );
}

export function replaceBytes(data: Uint8Array, from: string, to: string): Uint8Array {
  const hex = HexConverter.encode(data);
  const index = hex.indexOf(from);
  if (index < 0 || hex.indexOf(from, index + 1) >= 0) {
    throw new Error(`Pattern ${from} must occur exactly once`);
  }
  return HexConverter.decode(hex.slice(0, index) + to + hex.slice(index + from.length));
}
