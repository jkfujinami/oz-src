/**
 * libsodium の単一入口。
 *
 * 標準ビルド (`libsodium-wrappers`) には crypto_hash_sha256 と crypto_pwhash が
 * 含まれておらず、
 *   - Gossip PoW      : SHA-256  (本家 18.11)
 *   - NodeId PoW      : Argon2id (本家 18.5.3)
 *   - トリップ鍵の封印 : Argon2id + secretbox
 * のいずれも実装できない。よって sumo ビルドを使う。
 *
 * これに伴い argon2-browser への依存は廃止した。旧実装では
 * PoWEngine が type:2 (Argon2id)、pow.worker.ts が type:0 (Argon2d) を
 * 指定しており、送信側と Worker で別のハッシュを計算する不整合があったが、
 * 実装が 1 つになったことで構造的に起こり得なくなった。
 */
import sodium from 'libsodium-wrappers-sumo';

export default sodium;

/** 全ての暗号操作の前に await すること (WASM の初期化) */
export const sodiumReady: Promise<void> = sodium.ready;
