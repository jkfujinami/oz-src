// ============================================================================
// @oz/core — OZ P2P Anonymity Hardened Core Protocol Library
// ============================================================================

// ── Types ──
export { type GossipPacket, type IPeerManager, type IKeyManager, type IPoWEngine } from './types';

// ── Facade Node ──
export { OzNode, type OzNodeConfig } from './node/OzNode';

// ── Common ──
export { Encoding } from './common/Encoding';
export { createLogger, Logger, LogLevel, setLevel, currentLevels, installConsoleHandle } from './common/Logger';

// ── Crypto & Identity ──
export { default as sodium, sodiumReady } from './crypto/sodium';
export { CryptoEngine } from './crypto/CryptoEngine';
export { Identity } from './crypto/Identity';
export { KeyManager } from './crypto/KeyManager';
export { PoWEngine } from './crypto/PoWEngine';
export { DifficultyEstimator } from './crypto/DifficultyEstimator';
export { POW_POLICY, PACKET_VERSION, msToMinutes, minutesToMs, meetsDifficulty, derivePacketId, verifyPow, solvePow, toBytes } from './crypto/PowPolicy';
export { equixReady } from './crypto/equix/EquiX';
export { NodeIdentity, type NodeIdPowParams, NODE_ID_POW, NODE_ID_POW_FAST, trackerJoinMessage } from './crypto/NodeIdentity';
export { NodeIdentityStore } from './crypto/NodeIdentityStore';
export { PacketBuilder } from './crypto/PacketBuilder';

// ── Wire & Stream ──
export { WireType } from './network/wire/WireTypes';
export { WireCodec } from './network/wire/WireCodec';

// ── Network & Routing ──
export { PeerManager } from './network/PeerManager';
export { WebRTCPeer } from './network/WebRTCPeer';
export { SignalingClient, TrackerJoinError } from './network/SignalingClient';
export { TRACKER_PROTOCOL_VERSION, TRACKER_MAX_PEERS, type TrackerErrorCode, TRACKER_FRAME_LIMITS, TRACKER_MAX_FRAME_BYTES, type TrackerServerMessage, type TrackerJoin, type TrackerRelayOut, encodeTrackerServerMessage, encodeTrackerClientMessage, parseTrackerClientMessage, parseTrackerServerMessage, normalizeHostHeader } from './network/TrackerProtocol';
export {
  parseTrackerUrl,
  describeTrackerUrlError,
  TRACKER_STRING_PREFIX,
  createTrackerString,
  parseTrackerString,
  resolveTrackerWebSocketUrl,
  type TrackerEndpoint,
} from './network/TrackerUrl';
export { parseIceServers, deriveStunFromTracker, ICE_SERVERS_MAX, type IceServersResult } from './network/IceServers';
export { MessageDispatcher } from './network/MessageDispatcher';
export { GossipRouter } from './network/gossip/GossipRouter';
export { StorageService } from './network/storage/StorageService';
export { SLOT_BYTES } from './network/storage/SlotPow';
export { DandelionRouter } from './network/gossip/DandelionRouter';
export { OnionCircuit } from './network/onion/OnionCircuit';
export { SeenCache } from './network/gossip/SeenCache';
export { PEXHandler } from './network/PEXHandler';
export { RingMaintainer } from './network/RingMaintainer';
export { RateLimiter, type RateLimitConfig } from './network/RateLimiter';
export { PacketValidator } from './network/gossip/PacketValidator';

// ── 過去ログ (Guard の 72 時間バッファと追いつき) ──
export { RecentBuffer } from './network/history/RecentBuffer';

// ── Logic & Orchestration ──
export { BoardOrchestrator } from './logic/BoardOrchestrator';
export { ThreadOrchestrator } from './logic/ThreadOrchestrator';
export { ThreadRanker } from './logic/ThreadRanker';
export { type DAGPost } from './logic/ThreadDAGManager';
export { ThreadClosedError } from './logic/ThreadClosedError';
export type { ThreadState } from './logic/ThreadDAGManager';
export { THREAD_LIMITS } from './logic/ThreadLimits';
export type { ThreadMeta, BoardStatus, ThreadStatus } from './logic/types';
export { posterId } from './logic/PosterId';

// ── Storage ──
export { VAULT_PARAMS_FAST } from './storage/SecretVault';
export { IndexedDBStore, type BoardRecord } from './storage/IndexedDBStore';
export { WrongPassphraseError } from './storage/DataVault';

// ── Trusted guards ──
export { createGuardString, signGuardList, type MaintainerKeySet, type GuardListResult } from './trust/TrustedGuards';
export { type GuardStatus } from './trust/GuardManager';

// ── Files / Ring ──
export { closest } from './common/Ring';
export { CHUNK_SIZE, sanitizeFileName, sanitizeMime } from './files/FileFormat';
export { type FileLink, formatFileLink, parseFileLinks } from './files/FileLink';
export { type UploadProgress } from './files/FileUploader';

export { FileTransferError } from './files/FileTransfer';

// ── Ozzy v0.2 (4 MiB Uniform Chunks, RS(16,32), Split-Key KDF, R2 Gatekeeper Worker) ──
export * from './ozzy';
