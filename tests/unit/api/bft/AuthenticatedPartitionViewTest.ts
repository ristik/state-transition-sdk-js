import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  AuthenticatedPartitionView,
  PartitionViewAuthenticator,
} from '../../../../src/api/bft/AuthenticatedPartitionView.js';
import { PartitionView } from '../../../../src/api/bft/PartitionView.js';
import { RootTrustBase } from '../../../../src/api/bft/RootTrustBase.js';
import { UnicityCertificate } from '../../../../src/api/bft/UnicityCertificate.js';
import { UnicityTreeCertificate } from '../../../../src/api/bft/UnicityTreeCertificate.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { SealVerificationSession } from '../../../../src/api/bft/verification/SealVerificationSession.js';
import { Secp256k1SignatureVerifier } from '../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { HexConverter } from '../../../../src/util/HexConverter.js';

const PARTITION = 0x0a0b0c0dn;
const DIR = join(process.cwd(), 'tests/fixtures/uc-consolidation/partition-view/v1');

interface IVector {
  readonly enclosingUc: string;
  readonly epoch: number;
  readonly epochStartRound: number;
  readonly networkId: number;
  readonly nodeId: string;
  readonly shards: { readonly uc: string }[];
  readonly sigKey: string;
  readonly view: string;
}

function vector(name: string): IVector {
  return JSON.parse(readFileSync(join(DIR, `assembly-${name}.json`), 'utf8')) as IVector;
}

function trustBase(v: IVector): RootTrustBase {
  return RootTrustBase.fromJSON({
    changeRecordHash: null,
    epoch: String(v.epoch),
    epochStartRound: String(v.epochStartRound),
    networkId: v.networkId,
    previousEntryHash: null,
    quorumThreshold: '1',
    rootNodes: [{ nodeId: v.nodeId, sigKey: v.sigKey, stake: '1' }],
    signatures: {},
    stateHash: '00',
    version: '1',
  });
}

describe('AuthenticatedPartitionView', () => {
  const v = vector('4');
  const viewBytes = HexConverter.decode(v.view);
  const ucBytes = HexConverter.decode(v.enclosingUc);
  let verifier: Secp256k1SignatureVerifier;
  let verifySpy: jest.SpyInstance;
  let session: SealVerificationSession;

  beforeEach(() => {
    verifier = new Secp256k1SignatureVerifier();
    verifySpy = jest.spyOn(verifier, 'verify');
    session = new SealVerificationSession(trustBase(v), new UnicitySealQuorumSignaturesVerificationRule(verifier));
  });

  it('is only obtainable from the authenticator', () => {
    expect(() => new AuthenticatedPartitionView(Symbol('forged') as never, {} as never)).toThrow('can only be created');
  });

  it('yields the Go certificates, immutable to callers', async () => {
    const authenticated = await new PartitionViewAuthenticator(PARTITION, session).authenticate(viewBytes, ucBytes);
    const certificates = authenticated.assembleCertificates();
    expect(certificates.map((uc) => HexConverter.encode(uc.toCBOR()))).toEqual(v.shards.map((s) => s.uc));
    certificates.length = 0;
    expect(authenticated.assembleCertificates()).toHaveLength(4);
    expect(Object.isFrozen(authenticated)).toBe(true);
    const leaves = authenticated.leaves;
    leaves.length = 0;
    expect(authenticated.leaves).toHaveLength(4);
    expect(HexConverter.encode(authenticated.certificateOf(authenticated.scheme[2]).toCBOR())).toEqual(v.shards[2].uc);
    expect(authenticated.authority).toEqual(session.identity);
  });

  it('checks the tree and enclosing leaf before the seal, so an unproven view never reaches authentication', async () => {
    const authenticate = jest.spyOn(session, 'authenticate');
    const view = PartitionView.fromCBOR(viewBytes);
    const leaves = view.leaves;
    const wrong = new PartitionView(view.partitionId, [leaves[1], leaves[0], leaves[2], leaves[3]]);
    await expect(new PartitionViewAuthenticator(PARTITION, session).authenticate(wrong, ucBytes)).rejects.toMatchObject(
      { reason: 'topology' },
    );
    expect(authenticate).not.toHaveBeenCalled();

    const uc = UnicityCertificate.fromCBOR(ucBytes);
    const nil = new UnicityCertificate(
      uc.inputRecord,
      uc.technicalRecordHash,
      uc.shardConfigurationHash,
      uc.shardTreeCertificate,
      new UnicityTreeCertificate(uc.unicityTreeCertificate.partitionIdentifier, [null as never]),
      uc.unicitySeal,
    );
    await expect(new PartitionViewAuthenticator(PARTITION, session).authenticate(view, nil)).rejects.toMatchObject({
      reason: 'tree_mismatch',
    });
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('does not authenticate when the tree matches but the anchored authority does not', async () => {
    const other = new SealVerificationSession(
      RootTrustBase.fromJSON({ ...trustBase(v).toJSON(), epoch: String(v.epoch + 1) }),
      new UnicitySealQuorumSignaturesVerificationRule(verifier),
    );
    await expect(
      new PartitionViewAuthenticator(PARTITION, other).authenticate(viewBytes, ucBytes),
    ).rejects.toMatchObject({ reason: 'seal_invalid' });
    await expect(
      new PartitionViewAuthenticator(PARTITION + 1n, session).authenticate(viewBytes, ucBytes),
    ).rejects.toMatchObject({ reason: 'topology' });
  });

  it('memoizes by authority, partition, pins and bytes', async () => {
    const authenticator = new PartitionViewAuthenticator(PARTITION, session);
    const first = await authenticator.authenticate(viewBytes, ucBytes);
    expect(await authenticator.authenticate(viewBytes, ucBytes)).toBe(first);
    expect(verifySpy).toHaveBeenCalledTimes(1);

    const concurrent = new PartitionViewAuthenticator(PARTITION, session);
    const [a, b] = await Promise.all([
      concurrent.authenticate(viewBytes, ucBytes),
      concurrent.authenticate(viewBytes, ucBytes),
    ]);
    expect(a).toBe(b);
  });

  it('includes pins in the identity of the authenticator and of the views it produces', async () => {
    const view = PartitionView.fromCBOR(viewBytes);
    const hashes = new Map(view.leaves.map((l) => [l.shardId.toString(), l.shardConfigurationHash]));
    const plain = new PartitionViewAuthenticator(PARTITION, session);
    const pinned = new PartitionViewAuthenticator(PARTITION, session, { shardConfigurationHashes: hashes });
    const otherPins = new PartitionViewAuthenticator(PARTITION, session, {
      shardConfigurationHashes: new Map([['00', new Uint8Array(32).fill(1)]]),
    });
    expect(new Set([plain.identity, pinned.identity, otherPins.identity]).size).toEqual(3);
    expect((await plain.authenticate(view, ucBytes)).policy).not.toEqual(
      (await pinned.authenticate(view, ucBytes)).policy,
    );
    await expect(otherPins.authenticate(view, ucBytes)).rejects.toMatchObject({ reason: 'config_not_admitted' });
    // same pins in another map order are the same policy
    const reordered = new PartitionViewAuthenticator(PARTITION, session, {
      shardConfigurationHashes: new Map(Array.from(hashes.entries()).reverse()),
    });
    expect(reordered.identity).toEqual(pinned.identity);
  });

  it('keeps initial-state leaves null in the derived certificates', async () => {
    const initial = vector('4-initial');
    const s = new SealVerificationSession(
      trustBase(initial),
      new UnicitySealQuorumSignaturesVerificationRule(verifier),
    );
    const authenticated = await new PartitionViewAuthenticator(PARTITION, s).authenticate(
      HexConverter.decode(initial.view),
      HexConverter.decode(initial.enclosingUc),
    );
    const certificates = authenticated.assembleCertificates();
    expect(certificates.map((uc) => HexConverter.encode(uc.toCBOR()))).toEqual(initial.shards.map((x) => x.uc));
    expect(certificates[1].inputRecord.nullableHash).toBeNull();
    expect(certificates[1].inputRecord.nullableSummaryValue).toBeNull();
  });
});
