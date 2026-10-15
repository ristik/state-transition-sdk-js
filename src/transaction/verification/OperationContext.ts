import { IVerificationContext } from './IVerificationContext.js';

/**
 * The context of one verification operation: the caller's context with only the certificate verifier replaced by its
 * operation scoped form (see `UnicityCertificateVerifier.beginOperation`), so that identical certificates and seals of
 * the token and of every nested token are authenticated once. A verifier that does not scope (an injected
 * customization) keeps full control and the caller's context is returned as it is.
 *
 * @param {IVerificationContext} context The caller's context.
 * @returns {IVerificationContext} Context for one operation.
 */
export function beginOperationContext(context: IVerificationContext): IVerificationContext {
  const scoped = context.unicityCertificateVerifier.beginOperation?.();
  if (!scoped || scoped === context.unicityCertificateVerifier) {
    return context;
  }
  return Object.create(context, {
    unicityCertificateVerifier: { enumerable: true, value: scoped },
  }) as IVerificationContext;
}
