import { UnicitySealQuorumSignaturesVerificationRule } from './UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificate } from '../../UnicityCertificate.js';
import { CertificateVerificationResult } from '../CertificateVerdict.js';

/**
 * The native B1 bounds and formats of a unicity certificate (bft-core `b1ref` limits): a certificate outside them is refused as `malformed` before
 * anything is evaluated, the same class B1 gives it (`status = error`).
 *
 * - encoded certificate at most {@link MAX_CERTIFICATE_BYTES};
 * - shard tree path: exactly one sibling per shard bit, at most {@link MAX_SHARD_SIBLINGS};
 * - unicity tree path: at most {@link MAX_UNICITY_STEPS} steps;
 * - input record summary value at most {@link MAX_SUMMARY_BYTES};
 * - seal signatures: see {@link UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat}.
 */
export class UnicityCertificateFormatRule {
  public static readonly MAX_CERTIFICATE_BYTES = 24576;
  public static readonly MAX_SHARD_SIBLINGS = 256;
  public static readonly MAX_SUMMARY_BYTES = 256;
  public static readonly MAX_UNICITY_STEPS = 32;

  /**
   * @param {UnicityCertificate} certificate Certificate.
   * @returns {string|null} Why the certificate is malformed, or null.
   */
  public static failure(certificate: UnicityCertificate): string | null {
    try {
      const encoded = certificate.toCBOR().length;
      if (encoded > UnicityCertificateFormatRule.MAX_CERTIFICATE_BYTES) {
        return `Certificate of ${encoded} bytes exceeds ${UnicityCertificateFormatRule.MAX_CERTIFICATE_BYTES}.`;
      }
      const siblings = certificate.shardTreeCertificate.siblingHashList.length;
      if (siblings > UnicityCertificateFormatRule.MAX_SHARD_SIBLINGS) {
        return `${siblings} shard siblings exceed ${UnicityCertificateFormatRule.MAX_SHARD_SIBLINGS}.`;
      }
      if (siblings !== certificate.shardTreeCertificate.shard.length) {
        return `${siblings} shard siblings for a shard of depth ${certificate.shardTreeCertificate.shard.length}.`;
      }
      const steps = certificate.unicityTreeCertificate.steps.length;
      if (steps > UnicityCertificateFormatRule.MAX_UNICITY_STEPS) {
        return `${steps} unicity tree steps exceed ${UnicityCertificateFormatRule.MAX_UNICITY_STEPS}.`;
      }
      const summary = certificate.inputRecord.nullableSummaryValue?.length ?? 0;
      if (summary > UnicityCertificateFormatRule.MAX_SUMMARY_BYTES) {
        return `Summary value of ${summary} bytes exceeds ${UnicityCertificateFormatRule.MAX_SUMMARY_BYTES}.`;
      }
      return UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(certificate.unicitySeal);
    } catch {
      return 'The certificate is malformed.';
    }
  }

  /**
   * @param {UnicityCertificate} certificate Certificate.
   * @returns {CertificateVerificationResult} `ok` or `malformed`.
   */
  public static verify(certificate: UnicityCertificate): CertificateVerificationResult {
    const failure = UnicityCertificateFormatRule.failure(certificate);
    return new CertificateVerificationResult(
      'UnicityCertificateFormatRule',
      failure === null ? 'ok' : 'malformed',
      failure ?? '',
    );
  }
}
