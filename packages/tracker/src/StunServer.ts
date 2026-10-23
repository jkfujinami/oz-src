/**
 * 最小の STUN サーバ (RFC 5389 の Binding のみ)。
 *
 * ★ 第三者の STUN (Google など) を使うと、利用者の IP と接続時刻がその運営者に渡り、
 *   召喚状で引き出せる第三者になる。トラッカーには WebSocket ですでに全員の IP が見えているので、
 *   ここで STUN にも答えれば新たに漏れるものは無い。
 *
 * やること: Binding Request → XOR-MAPPED-ADDRESS だけを載せた Binding Success Response。
 * やらないこと: TURN、認証、FINGERPRINT 等の属性、Binding Request 以外への応答 (黙って捨てる)。
 *
 * ★ UDP は送信元を偽れるので、応答が反射・増幅の足場にならないようにする。
 *   - 応答は IPv4 で 32 バイト、IPv6 で 44 バイト (要求は最小 20 バイト。増幅は最大 2.2 倍)
 *   - 送信元 IP ごとに秒あたりの応答数を制限 (超過分は黙って捨てる。エラーも返さない)
 *   - 全体にも上限 (偽の送信元を大量に使われても、総量が一定を超えない)
 *   - 受け付ける要求の大きさにも上限 (大きい要求は WebRTC では来ない)
 *   - 何を受け取ったか (IP, 時刻) は記録しない。数えるだけ
 */
import dgram from 'node:dgram';
import net from 'node:net';

export const STUN_MAGIC_COOKIE = 0x2112a442;
const BINDING_REQUEST = 0x0001;
const BINDING_SUCCESS = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const HEADER_LEN = 20;
/** 要求の上限。ICE の Binding Request は SOFTWARE などを付けても数百バイトに収まる */
const MAX_REQUEST_LEN = 548;

export const STUN_LIMITS = {
  /** 1 つの送信元 IP あたり、1 秒に返す応答数 (バースト = 同じ値) */
  perIpPerSec: 10,
  /** 全体で 1 秒に返す応答数 */
  globalPerSec: 5000,
  /** 送信元ごとの状態を持つ上限 (超えたら古いものを掃除し、それでも超えるなら新規の IP は捨てる) */
  maxTrackedIps: 20_000,
} as const;

// ── コーデック ──

/** Binding Request なら transaction id (12 バイト) を返す。それ以外・壊れたものは null (例外は投げない) */
export function parseBindingRequest(msg: Uint8Array): Uint8Array | null {
  if (msg.length < HEADER_LEN || msg.length > MAX_REQUEST_LEN) return null;
  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const type = view.getUint16(0);
  // 先頭 2 ビットは 0 (RFC 5389 §6)。Binding Request (class=request, method=binding) のみ
  if ((type & 0xc000) !== 0 || type !== BINDING_REQUEST) return null;
  const bodyLen = view.getUint16(2);
  if (bodyLen % 4 !== 0 || bodyLen !== msg.length - HEADER_LEN) return null;
  if (view.getUint32(4) !== STUN_MAGIC_COOKIE) return null;
  // 属性の TLV が本体からはみ出さないことだけ確認する (中身は見ない)
  let off = HEADER_LEN;
  while (off < msg.length) {
    if (off + 4 > msg.length) return null;
    const len = view.getUint16(off + 2);
    off += 4 + len + ((4 - (len % 4)) % 4);
    if (off > msg.length) return null;
  }
  return msg.slice(8, HEADER_LEN);
}

/** "::ffff:1.2.3.4" は IPv4 として扱う。ゾーン ID (%eth0) は落とす */
function addressBytes(address: string): Uint8Array | null {
  const bare = address.split('%')[0]!;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(bare);
  const ip = mapped ? mapped[1]! : bare;
  const fam = net.isIP(ip);
  if (fam === 4) return Uint8Array.from(ip.split('.').map(Number));
  if (fam === 6) return ipv6Bytes(ip);
  return null;
}

function ipv6Bytes(ip: string): Uint8Array | null {
  // 末尾の IPv4 表記 (::1.2.3.4) を 16 進 2 グループへ
  let s = ip;
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const o = tail[1]!.split('.').map(Number);
    s = s.slice(0, s.length - tail[1]!.length) + ((o[0]! << 8) | o[1]!).toString(16) + ':' + ((o[2]! << 8) | o[3]!).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array<string>(fill).fill('0'), ...rest];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const v = Number.parseInt(groups[i]!, 16);
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) return null;
    out[i * 2] = v >> 8;
    out[i * 2 + 1] = v & 0xff;
  }
  return out;
}

/** Binding Success Response (XOR-MAPPED-ADDRESS のみ)。アドレスが解釈できなければ null */
export function buildBindingResponse(txId: Uint8Array, address: string, port: number): Uint8Array | null {
  if (txId.length !== 12 || !Number.isInteger(port) || port < 0 || port > 0xffff) return null;
  const addr = addressBytes(address);
  if (!addr) return null;
  const v6 = addr.length === 16;
  const attrLen = 4 + (v6 ? 16 : 4);
  const out = new Uint8Array(HEADER_LEN + 4 + attrLen);
  const view = new DataView(out.buffer);
  view.setUint16(0, BINDING_SUCCESS);
  view.setUint16(2, 4 + attrLen);
  view.setUint32(4, STUN_MAGIC_COOKIE);
  out.set(txId, 8);
  view.setUint16(20, ATTR_XOR_MAPPED_ADDRESS);
  view.setUint16(22, attrLen);
  out[24] = 0;
  out[25] = v6 ? 0x02 : 0x01;
  view.setUint16(26, port ^ (STUN_MAGIC_COOKIE >>> 16));
  // XOR の鍵: IPv4 は magic cookie、IPv6 は magic cookie + transaction id
  const key = new Uint8Array(16);
  new DataView(key.buffer).setUint32(0, STUN_MAGIC_COOKIE);
  key.set(txId, 4);
  for (let i = 0; i < addr.length; i++) out[28 + i] = addr[i]! ^ key[i]!;
  return out;
}

// ── 応答数の制限 ──

/** 送信元 IP ごとのトークンバケット + 全体の上限。時計は差し替えられる (テスト用) */
export class StunRateLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();
  private globalTokens: number = STUN_LIMITS.globalPerSec;
  private globalAt: number;

  constructor(private readonly now: () => number = Date.now) {
    this.globalAt = now();
  }

  allow(ip: string): boolean {
    const t = this.now();
    this.globalTokens = Math.min(STUN_LIMITS.globalPerSec, this.globalTokens + ((t - this.globalAt) / 1000) * STUN_LIMITS.globalPerSec);
    this.globalAt = t;
    if (this.globalTokens < 1) return false;

    let b = this.buckets.get(ip);
    if (!b) {
      if (this.buckets.size >= STUN_LIMITS.maxTrackedIps) {
        this.sweep(t);
        if (this.buckets.size >= STUN_LIMITS.maxTrackedIps) return false;
      }
      b = { tokens: STUN_LIMITS.perIpPerSec, at: t };
      this.buckets.set(ip, b);
    } else {
      b.tokens = Math.min(STUN_LIMITS.perIpPerSec, b.tokens + ((t - b.at) / 1000) * STUN_LIMITS.perIpPerSec);
      b.at = t;
    }
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    this.globalTokens -= 1;
    return true;
  }

  /** 満タンまで回復した (= 直近使っていない) 送信元の状態を捨てる */
  sweep(t: number = this.now()): void {
    for (const [ip, b] of this.buckets) {
      if (b.tokens + ((t - b.at) / 1000) * STUN_LIMITS.perIpPerSec >= STUN_LIMITS.perIpPerSec) this.buckets.delete(ip);
    }
  }

  get tracked(): number {
    return this.buckets.size;
  }
}

// ── サーバ ──

export interface StunCounts {
  responded: number;
  /** Binding Request ではない・壊れている */
  ignored: number;
  /** 制限で捨てた */
  limited: number;
}

export class StunServer {
  private socket: dgram.Socket | null = null;
  private limiter: StunRateLimiter;
  private sweeper: ReturnType<typeof setInterval> | null = null;
  private counts: StunCounts = { responded: 0, ignored: 0, limited: 0 };

  constructor(now?: () => number) {
    this.limiter = new StunRateLimiter(now);
  }

  /** port 0 なら OS が空きポートを選ぶ (テスト用)。実際のポートを返す */
  listen(port: number, host: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const family = net.isIP(host) === 6 ? 'udp6' : 'udp4';
      // '::' は IPv4 も受ける (dual-stack)。WebSocket 側の listen と同じ挙動
      const socket = dgram.createSocket({ type: family, ipv6Only: false });
      socket.on('message', (msg, rinfo) => this.onMessage(socket, msg, rinfo));
      // ★ 受信エラーでプロセスを落とさない
      socket.on('error', () => undefined);
      const onListenError = (err: Error) => reject(err);
      socket.once('error', onListenError);
      socket.bind(port, host, () => {
        socket.off('error', onListenError);
        this.socket = socket;
        this.sweeper = setInterval(() => this.limiter.sweep(), 30_000);
        this.sweeper.unref();
        resolve(socket.address().port);
      });
    });
  }

  private onMessage(socket: dgram.Socket, msg: Buffer, rinfo: dgram.RemoteInfo): void {
    try {
      const tx = parseBindingRequest(msg);
      if (!tx) {
        this.counts.ignored++;
        return;
      }
      if (!this.limiter.allow(rinfo.address)) {
        this.counts.limited++;
        return;
      }
      const res = buildBindingResponse(tx, rinfo.address, rinfo.port);
      if (!res) {
        this.counts.ignored++;
        return;
      }
      socket.send(res, rinfo.port, rinfo.address, () => undefined);
      this.counts.responded++;
    } catch {
      this.counts.ignored++;
    }
  }

  /** 前回からの件数を返して 0 に戻す (ログ用。IP や時刻は持たない) */
  takeCounts(): StunCounts {
    const c = this.counts;
    this.counts = { responded: 0, ignored: 0, limited: 0 };
    return c;
  }

  close(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    this.sweeper = null;
    const s = this.socket;
    this.socket = null;
    return new Promise((resolve) => {
      if (!s) return resolve();
      s.close(() => resolve());
    });
  }
}
