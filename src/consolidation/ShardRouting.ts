import { ConsolidationError } from './ConsolidationError.js';
import { PartitionView } from '../api/bft/PartitionView.js';
import { ShardId } from '../api/bft/ShardId.js';
import { IAggregatorClient } from '../api/IAggregatorClient.js';
import { NetworkId } from '../api/NetworkId.js';
import { StateId } from '../api/StateId.js';

/**
 * Aggregator of one shard, configured by the application. URLs and credentials live in the client the application
 * built; nothing a token or a response says can add or replace an endpoint.
 */
export interface IShardEndpoint {
  readonly client: IAggregatorClient;
  readonly shard: ShardId;
}

/**
 * Trusted routing configuration of one partition.
 */
export interface IShardRoutingOptions {
  /** Endpoints of the shards that may take part. Their ids must be shards of the scheme. */
  readonly endpoints: readonly IShardEndpoint[];
  /** Network the application expects; checked against the verification context's trust base. */
  readonly networkId?: NetworkId;
  /** Partition id the application expects (nonzero 32-bit). The caller's intent, never inferred from a response. */
  readonly partitionId: bigint;
  /** Complete sharding scheme of the partition: empty for a single shard partition. */
  readonly scheme: readonly ShardId[];
  /** Optional pinned shard configuration hashes by shard bit string, a stricter policy. */
  readonly shardConfigurationHashes?: ReadonlyMap<string, Uint8Array>;
}

/**
 * Immutable routing from a state id to its shard endpoint, from the admitted shard prefix topology. No modulo rule,
 * no inference from timestamps. Invalid configurations (incomplete or overlapping scheme, endpoints outside it,
 * duplicates) are rejected at construction.
 */
export class ShardRouting {
  public readonly networkId: NetworkId | null;
  public readonly partitionId: bigint;
  private readonly _scheme: readonly ShardId[];
  private readonly endpoints: readonly IShardEndpoint[];
  private readonly hashes: ReadonlyMap<string, Uint8Array> | undefined;

  /**
   * @param {IShardRoutingOptions} options Routing configuration.
   * @throws {ConsolidationError} `input` if the configuration is invalid.
   */
  public constructor(options: IShardRoutingOptions) {
    const input = (message: string, cause?: unknown): ConsolidationError =>
      new ConsolidationError('input', message, { cause, outcome: 'invalid_input' });

    if (options.partitionId <= 0n || options.partitionId > 0xffffffffn) {
      throw input('Partition id must be a nonzero 32-bit unsigned integer.');
    }
    let order: ShardId[];
    try {
      order = PartitionView.canonicalShardOrder(options.scheme);
    } catch (e) {
      throw input(`Invalid sharding scheme: ${e instanceof Error ? e.message : String(e)}`, e);
    }
    const seen = new Set<string>();
    for (const endpoint of options.endpoints) {
      const key = endpoint.shard.toString();
      if (!order.some((id) => id.equals(endpoint.shard))) {
        throw input(`Endpoint shard "${key}" is not in the scheme.`);
      }
      if (seen.has(key)) {
        throw input(`Duplicate endpoint for shard "${key}".`);
      }
      seen.add(key);
    }
    if (options.endpoints.length === 0) {
      throw input('At least one endpoint is required.');
    }

    this.partitionId = options.partitionId;
    this.networkId = options.networkId ?? null;
    this._scheme = options.scheme.slice();
    this.endpoints = options.endpoints.slice();
    this.hashes = options.shardConfigurationHashes
      ? new Map(Array.from(options.shardConfigurationHashes, ([shard, hash]) => [shard, new Uint8Array(hash)]))
      : undefined;
  }

  /**
   * @returns {ShardId[]} Copy of the configured scheme.
   */
  public get scheme(): ShardId[] {
    return this._scheme.slice();
  }

  /**
   * @returns {ReadonlyMap<string, Uint8Array>|undefined} Pinned configuration hashes, if configured.
   */
  public get shardConfigurationHashes(): ReadonlyMap<string, Uint8Array> | undefined {
    return this.hashes ? new Map(Array.from(this.hashes, ([shard, hash]) => [shard, new Uint8Array(hash)])) : undefined;
  }

  /**
   * Routing of a single shard partition served by one endpoint.
   *
   * @param {IAggregatorClient} client Client of the shard aggregator.
   * @param {bigint} partitionId Partition id.
   * @param {NetworkId} [networkId] Expected network.
   * @returns {ShardRouting} Routing.
   */
  public static single(client: IAggregatorClient, partitionId: bigint, networkId?: NetworkId): ShardRouting {
    return new ShardRouting({
      endpoints: [{ client, shard: ShardId.decode(new Uint8Array([0x80])) }],
      networkId,
      partitionId,
      scheme: [],
    });
  }

  /**
   * @param {StateId} stateId State id.
   * @returns {IShardEndpoint} Endpoint serving the state's shard.
   * @throws {ConsolidationError} `input` if no configured endpoint serves the state.
   */
  public route(stateId: StateId): IShardEndpoint {
    for (const endpoint of this.endpoints) {
      if (endpoint.shard.length === 0 || endpoint.shard.isPrefixOf(stateId.data)) {
        return endpoint;
      }
    }
    throw new ConsolidationError('input', `No configured endpoint serves ${stateId.toString()}.`, {
      outcome: 'invalid_input',
    });
  }
}
