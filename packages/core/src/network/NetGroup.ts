import sodium from '../crypto/sodium';

/**
 * NetGroup — 隣人の「ネットワーク上の出所」をまとめた粗い区分。
 *
 * Sybil 対策で、同じ出所の隣人が枠を占めすぎないようにするために使う。
 * 個々の IP そのものは保存も送信もしない (メモリ上で区分を求めるだけ)。
 *
 *   IPv4         → 上位 16 ビット (/16)
 *   IPv6         → 上位 48 ビット (/48)
 *   私設アドレス → 'lan' (同じ LAN の仲間同士を不当に不利にしない)
 *   mDNS (.local)→ 'lan'
 *   TURN リレー  → 'relay:' + リレーの /16 (同じリレー経由の相手は同じ出所)
 *   取れない     → 'unknown' (これも 1 つの区分として扱う)
 */
export function netGroupOf(address: string | undefined | null, candidateType?: string | null): string {
  if (!address) return 'unknown';
  const addr = address.trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (addr.endsWith('.local')) return 'lan';

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a > 255 || b > 255) return 'unknown';
    const group = `${a}.${b}`;
    if (candidateType === 'relay') return `relay:${group}`;
    if (isPrivateV4(a, b)) return 'lan';
    return `v4:${group}`;
  }

  if (addr.includes(':')) {
    const hextets = expandV6(addr);
    if (!hextets) return 'unknown';
    if (candidateType === 'relay') return `relay:${hextets.slice(0, 3).join(':')}`;
    const first = parseInt(hextets[0], 16);
    // fc00::/7 (ULA), fe80::/10 (link-local), ::1
    if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || hextets.join(':') === '0:0:0:0:0:0:0:1') {
      return 'lan';
    }
    return `v6:${hextets.slice(0, 3).join(':')}`;
  }

  return 'unknown';
}

function isPrivateV4(a: number, b: number): boolean {
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) // CGNAT
  );
}

/** IPv6 を 8 つの hextet (先頭の 0 を落とした小文字) に展開する。不正なら null */
function expandV6(addr: string): string[] | null {
  const zoneless = addr.split('%')[0];
  const parts = zoneless.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  // IPv4 埋め込み (::ffff:1.2.3.4) は扱わない (WebRTC では通常出てこない)
  if ([...head, ...tail].some(h => !/^[0-9a-f]{1,4}$/.test(h))) return null;
  const missing = 8 - head.length - tail.length;
  if (parts.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;
  return [...head, ...Array(missing).fill('0'), ...tail].map(h => parseInt(h, 16).toString(16));
}

/**
 * 1 区分あたりに許す隣人数。
 *
 * ★ 上限は固定値ではなく、これまでに見えた区分の数から決める。
 *   網が小さく区分が 1 つしか見えない段階では上限 = 全枠 (実質制限なし)。
 *   網が育って区分が増えるほど自動的に締まる。攻撃者が区分の数を水増ししても
 *   上限が厳しくなるだけで、防御側に不利にはならない。
 */
export function groupCap(maxDegree: number, distinctGroupsSeen: number): number {
  return Math.max(1, Math.ceil(maxDegree / Math.max(1, distinctGroupsSeen)));
}

// ── 経路の出所 (同じ家・同じ端末かどうか) ──

/** 私設アドレス・mDNS の相手 (同じ LAN にいる = 同じ公開 IP の仲間) */
export const ORIGIN_LAN = 'lan';
/** 比べられない (統計が取れない・TURN リレー経由など) */
export const ORIGIN_UNKNOWN = 'unknown';
/** まだ求めていない (接続直後)。経路には使わない */
export const ORIGIN_PENDING = 'pending';

/** 出所の鍵に混ぜる乱数 (起動ごとに変わる)。鍵から IP を逆算できないようにする */
let originSalt: Uint8Array | null = null;

/**
 * 経路の出所の鍵。オニオンの各段 (自分・Guard・M1) が同じ家・同じ端末にならないように比べる。
 *
 *   私設アドレス・mDNS (アドレスの載らない host 候補を含む) → 'lan'
 *   IPv4         → アドレスそのもの (/32。家庭は公開 IP を 1 つ共有する)
 *   IPv6         → 上位 56 ビット (家庭に配られる範囲。同じ家の端末はここが同じ)
 *   TURN リレー・取れない → 'unknown'
 *
 * ★ IP は持たない。起動ごとの乱数を鍵にしたハッシュにして、同じかどうかだけを比べる。
 * ★ Sybil の枠 ({@link netGroupOf}、/16) より細かい。こちらは「同じ人の端末」を見分けるためのもの。
 */
export function originKeyOf(address: string | undefined | null, candidateType?: string | null): string {
  if (candidateType === 'relay') return ORIGIN_UNKNOWN;
  // 統計にアドレスが載らない host 候補は mDNS (.local) の相手。直接届く host 同士 = 同じ LAN
  if (!address) return candidateType === 'host' ? ORIGIN_LAN : ORIGIN_UNKNOWN;
  const addr = address.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (addr.endsWith('.local')) return ORIGIN_LAN;

  let material: string | null = null;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4) {
    const octets = v4.slice(1, 5).map(Number);
    if (octets.some(o => o > 255)) return ORIGIN_UNKNOWN;
    if (isPrivateV4(octets[0], octets[1])) return ORIGIN_LAN;
    material = `v4:${octets.join('.')}`;
  } else if (addr.includes(':')) {
    const hextets = expandV6(addr);
    if (!hextets) return ORIGIN_UNKNOWN;
    const first = parseInt(hextets[0], 16);
    if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || hextets.join(':') === '0:0:0:0:0:0:0:1') {
      return ORIGIN_LAN;
    }
    // 上位 56 ビット = 先頭 3 つの hextet と 4 つ目の上位 8 ビット
    material = `v6:${hextets.slice(0, 3).join(':')}:${(parseInt(hextets[3], 16) >> 8).toString(16)}`;
  }
  if (!material) return ORIGIN_UNKNOWN;

  if (!originSalt) originSalt = crypto.getRandomValues(new Uint8Array(32));
  return 'o:' + sodium.to_hex(sodium.crypto_generichash(16, sodium.from_string(material), originSalt));
}

/**
 * 2 つの出所が同じか。比べられないもの (unknown) は同じとみなさない。
 * まだ求めていないもの (pending) は同じとみなす (分かるまでは使わない)。
 */
export function sameOrigin(a: string, b: string): boolean {
  if (a === ORIGIN_UNKNOWN || b === ORIGIN_UNKNOWN) return false;
  if (a === ORIGIN_PENDING || b === ORIGIN_PENDING) return true;
  return a === b;
}
