/**
 * The BFT partition of the Unicity aggregation layer: every network (mainnet network 1, testnet2 network 4, local
 * network 3) certifies its aggregation partition as partition 7.
 *
 * Application verification (genesis, transfers and nested tokens, consolidation and partition views) requires the
 * authenticated unicity certificate to be of this partition. It is a constant on purpose: no environment, constructor
 * or proof field can select another partition, so a proof never chooses the partition it is verified against. The
 * generic BFT codecs stay partition-agnostic.
 */
export const AGGREGATION_PARTITION_ID = 7n;
