import sodium from './sodium';
import { Encoding } from '../common/Encoding';
import { meetsDifficulty } from './PowPolicy';

/**
 * NodeIdentity — Bound Identity (本家 OZ 18.5.3)
 *
 * 旧実装の欠陥:
 *   peerId は randomBytes(16)、position は乱数で、両者に何の関係もなかった。
 *   さらに JOIN ハンドラが相手の申告した position を無検証で採用していた。
 *   結果として攻撃者は
 *     - 狙った topicHash の真隣に着地して K=5 の保持者になる
 *     - 特定ノードを取り囲んで eclipse する
 *     - リング上の連続した弧を占拠して範囲内の全コンテンツを支配する
 *   が自由にできた。
 *
 * 対策 (Bound Identity):
 *   peerId   = SHA256("OZ/v3/peerid"   ‖ pubkey)[0..16]
 *   position = SHA256("OZ/v3/position" ‖ peerId)[0..8] / 2^64
 *
 *   position は peerId の純粋関数なので、ネットワーク上で position を
 *   「申告」する必要がなくなる。受信側は peerId から自分で導出する。
 *   これだけで position 詐称という攻撃面が丸ごと消える。
 *
 *   さらに peerId は pubkey に束縛されるため、狙った座標に着地するには
 *   鍵をグラインドするしかない。Ed25519 の鍵生成は毎秒数十万回できるので、
 *   これを NodeId PoW (Argon2id) で殴って現実的でないコストにする。
 *
 *   ハッシュ関数の使い分けは本家 18.11 に従う:
 *     - Gossip PoW  : SHA-256   (全ノードが全件検証するので限界まで軽く)
 *     - NodeId PoW  : Argon2id  (検証は新規ピア登録時のみ。ASIC 優位を潰す)
 */

/** Argon2id ベースの NodeId PoW パラメータ */
export interface NodeIdPowParams {
  /** 要求する先頭ゼロビット数 */
  difficulty: number;
  /** Argon2id opslimit (t_cost) */
  opsLimit: number;
  /** Argon2id memlimit (bytes) */
  memLimit: number;
}

/**
 * 既定パラメータ。
 *
 * 実測 (libsodium WASM, Node 20): memLimit=1MiB / opsLimit=1 で 1 ハッシュ 3.4ms。
 *   - 採掘: difficulty=10 → 平均 1024 回 ≒ 3.5 秒。端末ごとに一度だけ払えばよく、
 *     以降は IndexedDB から復元するので起動のたびには掛からない。
 *   - 検証: 常に 1 ハッシュ = 3.4ms。隣人 16 人でも 55ms。
 *     ただし検証はそれなりに重いので、呼び出し側で
 *     (a) 安価な束縛検査と署名検査を先に通す (b) 結果を pubkey 単位でキャッシュする
 *     (c) レートリミッタで JOIN の頻度を絞る、の 3 点を必ず併用すること。
 *
 * difficulty を上げるほど座標グラインドのコストが 2 倍ずつ増えるが、
 * 初回起動の待ち時間も 2 倍になる。運用規模に応じて調整する値。
 */
export const NODE_ID_POW: NodeIdPowParams = {
  difficulty: 10,
  opsLimit: 1,
  memLimit: 1 << 20,
};

/** テストや開発環境で採掘待ちを避けるための軽量パラメータ */
export const NODE_ID_POW_FAST: NodeIdPowParams = {
  difficulty: 4,
  opsLimit: 1,
  memLimit: 8192,
};

/**
 * Argon2id の salt。ドメイン分離子として使う。
 * ★ crypto_pwhash の salt はちょうど 16 バイトでなければならない (違うと例外)。名前を変えるときは長さを合わせること。
 */
const NODE_ID_SALT = new TextEncoder().encode('OZ/v3/nodeid-pow');
if (NODE_ID_SALT.length !== 16) throw new Error('NODE_ID_SALT must be 16 bytes');

const PEER_ID_DOMAIN = new TextEncoder().encode('OZ/v3/peerid');
const POSITION_DOMAIN = new TextEncoder().encode('OZ/v3/position');
/**
 * v4: 署名対象を「この接続」に束縛した。v3 の署名 (challenge のみ) は受理しない。
 * ドメインを変えておくことで、旧クライアントとのハンドシェイクは確実に失敗する (fail-closed)。
 */
const JOIN_DOMAIN = new TextEncoder().encode('OZ/v4/join');
/**
 * トラッカーへの登録の署名ドメイン。P2P の JOIN とは分ける
 * (どちらかの署名を、もう一方の検証に流用されないように)。
 */
const TRACKER_JOIN_DOMAIN = new TextEncoder().encode('OZ/v1/tracker-join');

/** peerId のバイト長 (hex 表記では 32 文字) */
export const PEER_ID_BYTES = 16;

/** チャレンジのバイト長 */
export const CHALLENGE_BYTES = 32;

/**
 * NodeId PoW の解 (powCounter) の上限。ワイヤでは u32 で運ぶ (JOIN / PEX)。
 *
 * ★ 実測の難度 10 で平均 1,024 回、解が 2^32 を超える確率は事実上 0。u16 (65,535) だと
 *   難度を 12 以上に上げたときに採掘が実際に溢れうるので、1 つ上の u32 にしてある。
 *   難度を 24 以上に上げるなら、ワイヤの幅ごと見直すこと (solveNodeIdPow は溢れたら例外にする)。
 */
export const NODE_ID_POW_COUNTER_MAX = 0xffffffff;

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u64be(value: number | bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), false);
  return buf;
}

/**
 * ネットワーク上でピアが自分を名乗るときの主張。
 * position は含まない (peerId から導出できるため、載せると詐称の余地が生まれる)。
 */
export interface NodeClaim {
  /** hex 32 文字 */
  peerId: string;
  /** Ed25519 公開鍵 (32 バイト) */
  pubkey: Uint8Array;
  /** NodeId PoW の解 (u64) */
  powCounter: number;
}

/**
 * 所有証明つきの JOIN メッセージ。
 *
 * ★ challenge は載せない。検証者が自分で出した値を手元に持っているので、echo は帯域の無駄で、
 *   しかも「届いた challenge を信用してしまう」バグの入口になる。署名は検証者が手元の
 *   challenge で組み立てたメッセージに対して検証するので、別の challenge への署名は通らない。
 *   ワイヤでは peerId も載せない (pubkey から導出する。{@link NodeIdentity.derivePeerId})。
 */
export interface SignedNodeClaim extends NodeClaim {
  /** Ed25519(joinMessage(...))。{@link JoinBinding} を参照 */
  signature: Uint8Array;
}

/**
 * JOIN 署名を束縛する「この接続」の文脈。
 *
 * ★ 旧実装 (v3) は Ed25519(JOIN_DOMAIN ‖ challenge) しか署名していなかった。
 *   challenge はどの接続から来たものかを何も表さないので、攻撃者 M は
 *     1. T から受け取った challenge を、自分が正規ノード V へ送る HELLO に流用し
 *     2. V が返した署名付き JOIN をそのまま T へ転送する
 *   だけで、T に「M の端点 = V」と信じ込ませられた (中継型 MITM / identity misbinding)。
 *   NodeId PoW を一切払わずに任意の正規 ID の座標を占有でき、Bound Identity が無効化された。
 *
 *   v4 では、署名対象に
 *     - 検証者 (challenge を出した側) の peerId
 *     - 署名者自身の peerId
 *     - 両側の DTLS 証明書フィンガープリント (SDP の a=fingerprint)
 *   を含める。DTLS の秘密鍵はブラウザから持ち出せないので、別の接続で得た署名を
 *   この接続に流用することができない (M が DTLS を終端すると指紋が食い違う)。
 *
 * 署名側と検証側は同じ値を「自分の視点」から組み立てる:
 *   - signerFingerprint   : 署名者の DTLS 指紋 (署名側から見て local、検証側から見て remote)
 *   - verifierFingerprint : 検証者の DTLS 指紋 (署名側から見て remote、検証側から見て local)
 */
export interface JoinBinding {
  /** challenge を出した側 (検証者) の peerId */
  verifierId: string;
  /** 署名者の DTLS 指紋 */
  signerFingerprint: string;
  /** 検証者の DTLS 指紋 */
  verifierFingerprint: string;
}

function lengthPrefixed(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > 0xffff) throw new RangeError('JoinBinding field too long');
  const out = new Uint8Array(2 + bytes.length);
  new DataView(out.buffer).setUint16(0, bytes.length, false);
  out.set(bytes, 2);
  return out;
}

/** JOIN 署名の正準メッセージ。フィールド境界は長さ前置きで固定する */
export function joinMessage(challenge: Uint8Array, signerId: string, binding: JoinBinding): Uint8Array {
  return concat([
    JOIN_DOMAIN,
    challenge,
    lengthPrefixed(binding.verifierId),
    lengthPrefixed(signerId),
    lengthPrefixed(binding.signerFingerprint),
    lengthPrefixed(binding.verifierFingerprint),
  ]);
}

/**
 * トラッカー登録の正準メッセージ。
 *
 *   domain ‖ nonce (32 バイト, トラッカーが接続ごとに出す) ‖ lp(peerId) ‖ lp(trackerHost)
 *
 * trackerHost は「署名者が接続したつもりのトラッカー」のホスト名 (小文字、既定以外のポートを含む)。
 * これを含めないと、悪意あるトラッカー A が別のトラッカー B の nonce を中継して署名を得て、
 * 利用者になりすまして B に登録できてしまう。
 */
export function trackerJoinMessage(nonce: Uint8Array, peerId: string, trackerHost: string): Uint8Array {
  if (nonce.length !== CHALLENGE_BYTES) {
    throw new RangeError(`trackerJoinMessage: nonce must be ${CHALLENGE_BYTES} bytes`);
  }
  return concat([TRACKER_JOIN_DOMAIN, nonce, lengthPrefixed(peerId), lengthPrefixed(trackerHost.toLowerCase())]);
}

export class NodeIdentity {
  private constructor(
    public readonly peerId: string,
    public readonly position: number,
    public readonly pubkey: Uint8Array,
    private readonly privkey: Uint8Array,
    public readonly powCounter: number,
  ) {}

  // ── 導出 (純粋関数) ──

  /** peerId = SHA256("OZ/v3/peerid" ‖ pubkey)[0..16] を hex 化 */
  static derivePeerId(pubkey: Uint8Array): string {
    const h = sodium.crypto_hash_sha256(concat([PEER_ID_DOMAIN, pubkey]));
    return Encoding.toHex(h.slice(0, PEER_ID_BYTES));
  }

  /** Ed25519 公開鍵から X25519 (Curve25519) 暗号化用公開鍵を決定論的に導出する */
  static toCurve25519PubKey(ed25519Pubkey: Uint8Array): Uint8Array {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pubkey);
  }

  /** X25519 (Curve25519) 暗号化用公開鍵 (オニオンルーティング・P2P 代理フェッチ用) */
  get curvePubkey(): Uint8Array {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(this.pubkey);
  }

  /** X25519 (Curve25519) 暗号化用秘密鍵 */
  get curvePrivkey(): Uint8Array {
    return sodium.crypto_sign_ed25519_sk_to_curve25519(this.privkey);
  }

  /**
   * position = SHA256("OZ/v3/position" ‖ peerIdBytes)[0..8] / 2^64
   *
   * peerId から一意に定まるので、ネットワークから受け取った peerId に対して
   * 各ノードが独立に計算する。申告された position は一切信用しない。
   */
  static derivePosition(peerId: string): number {
    const idBytes = Encoding.fromHex(peerId);
    const h = sodium.crypto_hash_sha256(concat([POSITION_DOMAIN, idBytes]));
    const view = new DataView(h.buffer, h.byteOffset, 8);
    // 2^64 で割って [0, 1) に写す。Number は 53bit しか持てないが、
    // リング座標としての分解能は十分 (2^53 分割)。
    return Number(view.getBigUint64(0, false)) / 18446744073709551616;
  }

  /** NodeId PoW のハッシュ: Argon2id(pubkey ‖ counter, salt=固定) */
  static nodeIdPowHash(
    pubkey: Uint8Array,
    counter: number,
    params: NodeIdPowParams = NODE_ID_POW,
  ): Uint8Array {
    return sodium.crypto_pwhash(
      32,
      concat([pubkey, u64be(counter)]),
      NODE_ID_SALT,
      params.opsLimit,
      params.memLimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  }

  // ── 検証 ──

  /**
   * peerId が pubkey に束縛されており、かつ NodeId PoW を満たすかを検証する。
   * 所有証明 (署名) は含まないので、{@link verifySignedClaim} と併用すること。
   */
  static verifyClaim(claim: NodeClaim, params: NodeIdPowParams = NODE_ID_POW): boolean {
    if (typeof claim?.peerId !== 'string') return false;
    if (claim.peerId.length !== PEER_ID_BYTES * 2) return false;
    if (!/^[0-9a-f]+$/.test(claim.peerId)) return false;

    const pubkey = claim.pubkey instanceof Uint8Array ? claim.pubkey : null;
    if (!pubkey || pubkey.length !== sodium.crypto_sign_PUBLICKEYBYTES) return false;

    if (!Number.isSafeInteger(claim.powCounter) || claim.powCounter < 0 || claim.powCounter > NODE_ID_POW_COUNTER_MAX) return false;

    // 1. peerId が pubkey のハッシュであること
    if (NodeIdentity.derivePeerId(pubkey) !== claim.peerId) return false;

    // 2. NodeId PoW を満たすこと (座標グラインドのコストを引き上げる)
    if (params.difficulty > 0) {
      const hash = NodeIdentity.nodeIdPowHash(pubkey, claim.powCounter, params);
      if (!meetsDifficulty(hash, params.difficulty)) return false;
    }

    return true;
  }

  /**
   * 所有証明つきの検証。
   *
   * challenge は「検証する側が生成してその場で送った乱数」でなければならない。
   * これが無いと、攻撃者が他人の JOIN を傍受してそのまま再生し、
   * 被害者になりすませてしまう (replay)。
   */
  static verifySignedClaim(
    claim: SignedNodeClaim,
    expectedChallenge: Uint8Array,
    binding: JoinBinding,
    params: NodeIdPowParams = NODE_ID_POW,
  ): boolean {
    const signature = claim?.signature instanceof Uint8Array ? claim.signature : null;
    if (!signature) return false;
    if (!(expectedChallenge instanceof Uint8Array) || expectedChallenge.length !== CHALLENGE_BYTES) return false;
    if (signature.length !== sodium.crypto_sign_BYTES) return false;

    // 安価な署名検査を先に通し、重い NodeId PoW (Argon2id) は最後に回す
    if (typeof claim.peerId !== 'string') return false;
    if (!(claim.pubkey instanceof Uint8Array) || claim.pubkey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
      return false;
    }
    let signatureOk = false;
    try {
      signatureOk = sodium.crypto_sign_verify_detached(
        signature,
        joinMessage(expectedChallenge, claim.peerId, binding),
        claim.pubkey,
      );
    } catch {
      return false;
    }
    if (!signatureOk) return false;

    return NodeIdentity.verifyClaim(claim, params);
  }

  /** 検証する側が送るチャレンジを生成する */
  static newChallenge(): Uint8Array {
    return sodium.randombytes_buf(CHALLENGE_BYTES);
  }

  // ── 生成・復元 ──

  /**
   * 新しいノード identity を採掘する。
   *
   * NodeId PoW を満たす鍵ペアが出るまで鍵生成を繰り返す方式ではなく、
   * 鍵ペアは 1 つ固定してカウンタを回す。こうすると秘密鍵が変わらないので
   * 「一度採掘したら永続化して使い回す」が成立する。
   */
  static async mine(params: NodeIdPowParams = NODE_ID_POW): Promise<NodeIdentity> {
    await sodium.ready;
    const kp = sodium.crypto_sign_keypair();
    const counter = NodeIdentity.solveNodeIdPow(kp.publicKey, params);
    return NodeIdentity.fromKeyPair(kp.publicKey, kp.privateKey, counter);
  }

  /** 与えられた公開鍵に対する PoW 解を探索する */
  static solveNodeIdPow(pubkey: Uint8Array, params: NodeIdPowParams = NODE_ID_POW): number {
    if (params.difficulty <= 0) return 0;
    for (let counter = 0; counter <= NODE_ID_POW_COUNTER_MAX; counter++) {
      if (meetsDifficulty(NodeIdentity.nodeIdPowHash(pubkey, counter, params), params.difficulty)) {
        return counter;
      }
    }
    throw new Error('NodeIdentity: PoW search exhausted');
  }

  /** 永続化済みの鍵ペアから復元する */
  static fromKeyPair(pubkey: Uint8Array, privkey: Uint8Array, powCounter: number): NodeIdentity {
    const peerId = NodeIdentity.derivePeerId(pubkey);
    const position = NodeIdentity.derivePosition(peerId);
    return new NodeIdentity(peerId, position, pubkey, privkey, powCounter);
  }

  // ── 自分を名乗る ──

  /** 署名なしの主張 (トラッカーへの join 等) */
  claim(): NodeClaim {
    return { peerId: this.peerId, pubkey: this.pubkey, powCounter: this.powCounter };
  }

  /**
   * 相手のチャレンジに署名した主張 (P2P の JOIN)。
   *
   * challenge は固定長しか受け付けない。任意長のバイト列に署名して返すと、
   * 署名オラクルとして悪用される余地が広がる。
   */
  signClaim(challenge: Uint8Array, binding: JoinBinding): SignedNodeClaim {
    if (challenge.length !== CHALLENGE_BYTES) {
      throw new RangeError(`signClaim: challenge must be ${CHALLENGE_BYTES} bytes`);
    }
    return {
      ...this.claim(),
      signature: sodium.crypto_sign_detached(joinMessage(challenge, this.peerId, binding), this.privkey),
    };
  }

  /**
   * トラッカーへの登録の所有証明。トラッカーが接続ごとに出す nonce と、
   * 接続先のホスト名に署名する ({@link trackerJoinMessage})。
   */
  signTrackerJoin(nonce: Uint8Array, trackerHost: string): Uint8Array {
    return sodium.crypto_sign_detached(trackerJoinMessage(nonce, this.peerId, trackerHost), this.privkey);
  }

  /**
   * トラッカー側の検証。Bound Identity (peerId = hash(pubkey) + NodeId PoW) に加えて、
   * その公開鍵の秘密鍵で、この接続の nonce とこのトラッカーのホスト名に署名していること。
   *
   * ★ peerId・pubkey・powCounter は公開情報 (P2P の JOIN で全隣人に渡る) なので、
   *   それだけを確かめても他人の ID での登録を防げない。署名が必須。
   */
  static verifyTrackerJoin(
    claim: NodeClaim,
    nonce: Uint8Array,
    trackerHost: string,
    signature: Uint8Array,
    params: NodeIdPowParams = NODE_ID_POW,
  ): boolean {
    if (!(nonce instanceof Uint8Array) || nonce.length !== CHALLENGE_BYTES) return false;
    if (!(signature instanceof Uint8Array) || signature.length !== sodium.crypto_sign_BYTES) return false;
    if (typeof trackerHost !== 'string' || trackerHost.length === 0 || trackerHost.length > 255) return false;
    if (!NodeIdentity.verifyClaim(claim, params)) return false;
    try {
      return sodium.crypto_sign_verify_detached(
        signature,
        trackerJoinMessage(nonce, claim.peerId, trackerHost),
        claim.pubkey,
      );
    } catch {
      return false;
    }
  }

  /**
   * Ozzy の中継 Worker の広告 (ozzy/WorkerPool) に署名する。署名対象はここで組み立てる
   * (任意のバイト列に署名させない: 署名オラクルにしない)。
   */
  signOzzyWorkerAd(url: string, expiresMin: number): Uint8Array {
    return sodium.crypto_sign_detached(ozzyWorkerAdMessage(this.pubkey, url, expiresMin), this.privkey);
  }

  /** 永続化用。秘密鍵を含むので取り扱い注意 */
  exportSecret(): { pubkey: Uint8Array; privkey: Uint8Array; powCounter: number } {
    return { pubkey: this.pubkey, privkey: this.privkey, powCounter: this.powCounter };
  }
}

/** Ozzy の中継 Worker の広告の署名対象: ドメイン ‖ 公開鍵 ‖ 期限 (分) u32 ‖ lp8(URL) */
export function ozzyWorkerAdMessage(pubkey: Uint8Array, url: string, expiresMin: number): Uint8Array {
  const domain = new TextEncoder().encode('ozzy-worker-ad-v1');
  const u = new TextEncoder().encode(url);
  if (u.length > 255) throw new RangeError('url too long');
  const out = new Uint8Array(domain.length + pubkey.length + 4 + 1 + u.length);
  let o = 0;
  out.set(domain, o); o += domain.length;
  out.set(pubkey, o); o += pubkey.length;
  new DataView(out.buffer).setUint32(o, expiresMin >>> 0, false); o += 4;
  out[o++] = u.length;
  out.set(u, o);
  return out;
}
