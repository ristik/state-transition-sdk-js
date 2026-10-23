/**
 * Thrown when a split output's payment data does not decode, with the decoder
 * passed to the split, to exactly the assets it declares.
 */
export class SplitPayloadMismatchError extends Error {
  public constructor(reason: string, options?: { cause?: unknown }) {
    super(`Split output payment data does not match its declared assets: ${reason}.`, options);
  }
}
