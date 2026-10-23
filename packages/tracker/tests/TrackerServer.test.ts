import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import WebSocket from 'ws';
import {
  sodium,
  sodiumReady,
  NodeIdentity,
  NODE_ID_POW_FAST,
  RateLimiter,
  SignalingClient,
  TrackerJoinError,
  TRACKER_FRAME_LIMITS,
  TRACKER_PROTOCOL_VERSION,
  encodeTrackerClientMessage,
  parseTrackerServerMessage,
  type TrackerJoin,
} from '@oz/core';
import { TrackerServer, type TrackerOptions } from '../src';

const PARAMS = NODE_ID_POW_FAST;
const LOOSE = new RateLimiter({ join: { ratePerSec: 1000, burst: 1000 }, relay: { ratePerSec: 1000, burst: 1000 } });

let http: Server;
let tracker: TrackerServer;
let port: number;
let url: string;
let logs: string[];

let alice: NodeIdentity;
let bob: NodeIdentity;
let mallory: NodeIdentity;

beforeAll(async () => {
  await sodiumReady;
  [alice, bob, mallory] = await Promise.all([1, 2, 3].map(() => NodeIdentity.mine(PARAMS)));
});

async function startTracker(options: TrackerOptions = {}) {
  http = createServer();
  logs = [];
  tracker = new TrackerServer(http, { powParams: PARAMS, rateLimiter: LOOSE, log: (l) => logs.push(l), ...options });
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  port = (http.address() as AddressInfo).port;
  url = `ws://127.0.0.1:${port}/ws`;
}

async function stopTracker() {
  tracker.shutdown();
  http.closeAllConnections();
  await new Promise<void>((resolve) => http.close(() => resolve()));
}

beforeEach(() => startTracker());
afterEach(() => stopTracker());

/** 正しい join フレーム。overrides で各フィールドを書き換えられる (peerId は pubkey から導出されるので載らない) */
function joinFrame(
  identity: NodeIdentity,
  nonce: Uint8Array,
  host: string,
  signer: NodeIdentity = identity,
  overrides: Partial<TrackerJoin> = {},
): Uint8Array {
  return encodeTrackerClientMessage({
    type: 'join',
    v: TRACKER_PROTOCOL_VERSION,
    peerId: identity.peerId,
    pubkey: identity.pubkey,
    powCounter: identity.powCounter,
    host,
    sig: signer.signTrackerJoin(nonce, host),
    ...overrides,
  });
}

/** 生の WebSocket で話すクライアント (攻撃者の視点で任意のメッセージを送れる) */
class RawClient {
  public messages: any[] = [];
  public closed = false;
  private constructor(public ws: WebSocket) {}

  static async open(path = '/ws', headers: Record<string, string> = {}): Promise<RawClient> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`, { headers, handshakeTimeout: 1000 });
    const client = new RawClient(ws);
    // ★ サーバのフレームはバイナリ。core の検証関数でそのまま読む (テキストは無視)
    ws.on('message', (raw: Buffer, isBinary: boolean) => {
      if (!isBinary) return;
      const msg = parseTrackerServerMessage(raw);
      if (msg) client.messages.push(msg);
    });
    ws.on('close', () => { client.closed = true; });
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });
    return client;
  }

  /** Uint8Array はそのまま、オブジェクトは core の符号化でバイナリにして送る */
  send(msg: unknown): void {
    if (msg instanceof Uint8Array) this.ws.send(msg);
    else this.ws.send(encodeTrackerClientMessage(msg as any));
  }

  /** 文字列はテキストフレームとして送る (サーバは受け付けない) */
  sendText(text: string): void {
    this.ws.send(text);
  }

  async next(predicate: (m: any) => boolean, timeoutMs = 3000): Promise<any> {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      const found = this.messages.find(predicate);
      if (found) return found;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error(`timeout waiting for message; got ${JSON.stringify(this.messages)}`);
  }

  async waitClosed(timeoutMs = 3000): Promise<void> {
    const started = Date.now();
    while (!this.closed && Date.now() - started < timeoutMs) await new Promise((r) => setTimeout(r, 5));
    if (!this.closed) throw new Error('connection was not closed');
  }

  async nonce(): Promise<Uint8Array> {
    const hello = await this.next((m) => m.type === 'hello');
    return hello.nonce;
  }

  /** 正しい手順で登録する。overrides で各フィールドを書き換えられる */
  async joinAs(identity: NodeIdentity, overrides: Partial<TrackerJoin> = {}, signer: NodeIdentity = identity, host = `127.0.0.1:${port}`) {
    const nonce = await this.nonce();
    this.send(joinFrame(identity, nonce, host, signer, overrides));
  }

  async joined(identity: NodeIdentity): Promise<any[]> {
    await this.joinAs(identity);
    return (await this.next((m) => m.type === 'peers')).peers;
  }

  close(): void {
    this.ws.close();
  }
}

const Encoding16 = (hex: string) => sodium.from_hex(hex);
const SDP = { sdp: { type: 'offer', sdp: 'v=0' } };
const settle = (ms = 100) => new Promise((r) => setTimeout(r, ms));

describe('トラッカー v3: 登録の手順', () => {
  it('接続ごとに異なる 32 バイトの nonce を hello で送る', async () => {
    const a = await RawClient.open();
    const b = await RawClient.open();
    const [na, nb] = [await a.nonce(), await b.nonce()];
    expect(na.length).toBe(32);
    expect(sodium.to_hex(na)).not.toBe(sodium.to_hex(nb));
    const hello = a.messages[0];
    expect(hello).toEqual({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: expect.any(Uint8Array) });
    a.close(); b.close();
  });

  it('正しい所有証明つきの join を受理し、peerId だけのリストを返す', async () => {
    const a = await RawClient.open();
    expect(await a.joined(alice)).toEqual([]);
    const b = await RawClient.open();
    const peers = await b.joined(bob);
    expect(peers).toEqual([{ peerId: alice.peerId }]);
    expect(tracker.sessionCount).toBe(2);
    a.close(); b.close();
  });

  it('core の SignalingClient と実際に通信して登録できる (クライアントとサーバの形式が一致)', async () => {
    const client = new SignalingClient(url, { WebSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket });
    const peers: any[] = [];
    client.on('peers', (p) => peers.push(...p));
    await client.connect({ claim: alice.claim(), identity: alice });
    expect(client.isConnected).toBe(true);
    expect(tracker.sessionCount).toBe(1);

    // 2 人目も登録でき、1 人目が紹介される
    const client2 = new SignalingClient(url, { WebSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket });
    const peers2: any[] = [];
    client2.on('peers', (p) => peers2.push(...p));
    await client2.connect({ claim: bob.claim(), identity: bob });
    expect(peers2).toEqual([{ peerId: alice.peerId }]);

    // SignalingClient 同士で relay が届く
    const relayed = new Promise<[string, any]>((resolve) => client.on('relay', (from, payload) => resolve([from, payload])));
    client2.sendRelay(alice.peerId, { sdp: { type: 'offer', sdp: 'v=0' } });
    expect(await relayed).toEqual([bob.peerId, { sdp: { type: 'offer', sdp: 'v=0' } }]);

    client.disconnect();
    client2.disconnect();
  });

  it('hello より前の join・未登録の relay・壊れたメッセージは、理由を返して切断する', async () => {
    for (const [msg, code] of [
      [new Uint8Array([0xee, 1, 2]), 'bad-message'], // 未知の種別
      [new Uint8Array([0x11]), 'bad-message'], // 切り詰めた join
      [new Uint8Array([0x01, 3, ...new Uint8Array(32)]), 'bad-message'], // 方向違い (hello はサーバ → ノードだけ)
      [{ type: 'relay', targetPeerId: alice.peerId, payload: { sdp: { type: 'offer', sdp: 'v=0' } } }, 'not-joined'],
    ] as const) {
      const c = await RawClient.open();
      await c.nonce();
      c.send(msg);
      expect((await c.next((m) => m.type === 'error')).code).toBe(code);
      await c.waitClosed();
    }
  });

  it('テキストフレーム (旧 JSON) は受け付けない', async () => {
    const c = await RawClient.open();
    await c.nonce();
    c.sendText(JSON.stringify({ type: 'join', v: 2 }));
    expect((await c.next((m) => m.type === 'error')).code).toBe('bad-message');
    await c.waitClosed();
  });

  it('上限を超える大きさのフレームは読まずに切る', async () => {
    const c = await RawClient.open();
    await c.nonce();
    c.send(new Uint8Array(TRACKER_FRAME_LIMITS.RELAY + 1).fill(0x04));
    await c.waitClosed();
  });

  it('種別ごとの上限: 余りバイトのある join・長すぎる join は拒否する', async () => {
    const c = await RawClient.open();
    const nonce = await c.nonce();
    const ok = joinFrame(alice, nonce, `127.0.0.1:${port}`);
    const trailing = new Uint8Array(ok.length + 1);
    trailing.set(ok);
    c.send(trailing);
    expect((await c.next((m) => m.type === 'error')).code).toBe('bad-message');
    await c.waitClosed();

    const d = await RawClient.open();
    await d.nonce();
    d.send(new Uint8Array(TRACKER_FRAME_LIMITS.JOIN + 1).fill(0x11));
    expect((await d.next((m) => m.type === 'error')).code).toBe('bad-message');
  });

  it('期限内に登録しない接続は切る', async () => {
    await stopTracker();
    await startTracker({ handshakeTimeoutMs: 100 });
    const c = await RawClient.open();
    await c.nonce();
    expect((await c.next((m) => m.type === 'error')).code).toBe('timeout');
    await c.waitClosed();
  });

  it('指定のパス以外では WebSocket を受け付けない', async () => {
    await stopTracker();
    await startTracker({ exclusiveUpgrade: true });
    await expect(RawClient.open('/wsx')).rejects.toBeTruthy();
    await expect(RawClient.open('/other')).rejects.toBeTruthy();
    const ok = await RawClient.open('/ws?x=1');
    await ok.nonce();
    ok.close();
  });
});

describe('トラッカー v3: 他人の ID での登録 (乗っ取り) を防ぐ', () => {
  it('★公開情報 (peerId・pubkey・powCounter) を写しても、署名が無ければ登録できない', async () => {
    const victim = await RawClient.open();
    await victim.joined(alice);

    // 攻撃者は alice の公開情報をそのまま使い、自分の鍵で署名する
    const attacker = await RawClient.open();
    await attacker.joinAs(alice, {}, mallory);
    expect((await attacker.next((m) => m.type === 'error')).code).toBe('bad-signature');
    await attacker.waitClosed();
    expect(tracker.sessionCount).toBe(1);

    // alice 宛ての relay は本人に届く
    const sender = await RawClient.open();
    await sender.joined(bob);
    const sdp = { sdp: { type: 'offer', sdp: 'v=0' } };
    sender.send({ type: 'relay', targetPeerId: alice.peerId, payload: sdp });
    expect(await victim.next((m) => m.type === 'relay')).toEqual({ type: 'relay', senderId: bob.peerId, payload: sdp });
    victim.close(); sender.close();
  });

  it('★本人が不在のときでも、他人の ID では登録できない', async () => {
    const attacker = await RawClient.open();
    await attacker.joinAs(alice, {}, mallory);
    expect((await attacker.next((m) => m.type === 'error')).code).toBe('bad-signature');
    expect(tracker.sessionCount).toBe(0);
  });

  it('★別の接続の nonce への署名は使い回せない', async () => {
    const first = await RawClient.open();
    const nonce = await first.nonce();
    const host = `127.0.0.1:${port}`;
    const sig = alice.signTrackerJoin(nonce, host);

    // 盗んだ署名を別の接続で使う
    const replay = await RawClient.open();
    await replay.nonce();
    replay.send(joinFrame(alice, nonce /* 盗んだ nonce ではなく、署名だけ流用 */, host, alice, { sig }));
    expect((await replay.next((m) => m.type === 'error')).code).toBe('bad-signature');
    first.close();
  });

  it('★別のトラッカー宛ての署名は受け付けない (中継による流用の防止)', async () => {
    const c = await RawClient.open();
    // 署名も host も「evil.example」宛て。nonce はこの接続のもの
    await c.joinAs(alice, {}, alice, 'evil.example');
    expect((await c.next((m) => m.type === 'error')).code).toBe('bad-host');
    expect(tracker.sessionCount).toBe(0);
  });

  it('allowedHosts を指定すると、Host ヘッダではなくその一覧と照合する (リバースプロキシ配下)', async () => {
    await stopTracker();
    await startTracker({ allowedHosts: ['Tracker.Example.org', 'tracker.example.org:443'] });
    const c = await RawClient.open();
    await c.joinAs(alice, {}, alice, 'tracker.example.org');
    expect(await c.next((m) => m.type === 'peers')).toBeTruthy();

    const d = await RawClient.open();
    await d.joinAs(bob); // 127.0.0.1:port は一覧に無い
    expect((await d.next((m) => m.type === 'error')).code).toBe('bad-host');
    c.close();
  });

  it('★他人の PoW (powCounter) を自分の pubkey に付けても拒否する (Bound Identity)', async () => {
    // peerId はワイヤに載らず pubkey から導出されるので、「別の peerId を名乗る」ことは構造上できない。
    // 残る攻撃は「他人の powCounter の流用」。bob の鍵に、PoW を満たさない counter を付ける
    let counter = alice.powCounter;
    while (NodeIdentity.verifyClaim({ peerId: bob.peerId, pubkey: bob.pubkey, powCounter: counter }, PARAMS)) counter++;
    const c = await RawClient.open();
    await c.joinAs(bob, { powCounter: counter });
    expect((await c.next((m) => m.type === 'error')).code).toBe('invalid-identity');
  });

  it('★NodeId PoW を解いていない identity を拒否する (Sybil の関門)', async () => {
    let bad: NodeIdentity | null = null;
    for (let i = 0; i < 300 && !bad; i++) {
      const kp = sodium.crypto_sign_keypair();
      const candidate = NodeIdentity.fromKeyPair(kp.publicKey, kp.privateKey, 0);
      if (!NodeIdentity.verifyClaim(candidate.claim(), PARAMS)) bad = candidate;
    }
    expect(bad).not.toBeNull();
    const c = await RawClient.open();
    await c.joinAs(bad!);
    expect((await c.next((m) => m.type === 'error')).code).toBe('invalid-identity');
  });

  it('旧版の join は受け付けない (v1 / v2 の番号、署名なしの形)', async () => {
    for (const v of [1, 2]) {
      const c = await RawClient.open();
      await c.joinAs(alice, { v });
      expect((await c.next((m) => m.type === 'error')).code).toBe('unsupported-version');
    }

    // 署名なし (pubkey ‖ powCounter だけ) は長さ不足
    const legacy = await RawClient.open();
    await legacy.nonce();
    legacy.send(new Uint8Array([0x11, 1, ...alice.pubkey, 0, 0, 0, 1]));
    expect((await legacy.next((m) => m.type === 'error')).code).toBe('bad-message');
  });

  it('形式不正な join は拒否する', async () => {
    const host = `127.0.0.1:${port}`;
    const cases: Array<[string, (ok: Uint8Array) => Uint8Array]> = [
      ['pubkey が別人 (署名と合わない)', (f) => { const g = f.slice(); g.set(bob.pubkey, 2); return g; }],
      ['sig が壊れている', (f) => { const g = f.slice(); g[2 + 32 + 4] ^= 0xff; return g; }],
      ['host の長さが実長と違う', (f) => { const g = f.slice(); g[g.length - host.length - 1] = host.length + 1; return g; }],
      ['host に大文字', (f) => { const g = f.slice(); g[g.length - 1] = 'X'.charCodeAt(0); return g; }],
      ['host に空白', (f) => { const g = f.slice(); g[g.length - 1] = 0x20; return g; }],
      ['host が不正な UTF-8', (f) => { const g = f.slice(); g[g.length - 1] = 0xff; return g; }],
      ['切り詰め', (f) => f.slice(0, f.length - 3)],
    ];
    for (const [name, mutate] of cases) {
      const c = await RawClient.open();
      const nonce = await c.nonce();
      c.send(mutate(joinFrame(alice, nonce, host)));
      const err = await c.next((m) => m.type === 'error');
      expect(err.code, name).toMatch(/bad-message|invalid-identity|bad-host|bad-signature/);
      await c.waitClosed();
    }
    expect(tracker.sessionCount).toBe(0);
  });

  it('本人が新しい接続で登録し直すと、古い接続を置き換える (再接続)', async () => {
    const first = await RawClient.open();
    await first.joined(alice);
    const second = await RawClient.open();
    await second.joined(alice);
    await first.waitClosed();
    expect(tracker.sessionCount).toBe(1);

    // 古い接続の close で、新しい登録が消えない
    await settle(50);
    expect(tracker.sessionCount).toBe(1);
    const sender = await RawClient.open();
    await sender.joined(bob);
    sender.send({ type: 'relay', targetPeerId: alice.peerId, payload: SDP });
    expect((await second.next((m) => m.type === 'relay')).senderId).toBe(bob.peerId);
  });

  it('1 つの接続で 2 回目の登録はしない', async () => {
    const c = await RawClient.open();
    await c.joined(alice);
    c.send(joinFrame(bob, new Uint8Array(32), `127.0.0.1:${port}`));
    expect((await c.next((m) => m.type === 'error')).code).toBe('bad-message');
    expect(tracker.sessionCount).toBe(1);
  });

  it('切断したら登録は消え、同じ ID で登録し直せる', async () => {
    const first = await RawClient.open();
    await first.joined(alice);
    first.close();
    await first.waitClosed();
    await settle(50);
    expect(tracker.sessionCount).toBe(0);
    const second = await RawClient.open();
    await second.joined(alice);
    expect(tracker.sessionCount).toBe(1);
  });
});

describe('トラッカー v3: relay', () => {
  it('★送信元は接続から決め、payload に書かれた送信元は信用しない', async () => {
    const a = await RawClient.open();
    await a.joined(alice);
    const m = await RawClient.open();
    await m.joined(mallory);

    // ★ バイナリの中継には送信元の欄が無い (宛先だけ)。サーバが接続から付ける
    m.send({ type: 'relay', targetPeerId: alice.peerId, payload: SDP });
    const got = await a.next((x) => x.type === 'relay');
    expect(got.senderId).toBe(mallory.peerId);
    expect(got.payload).toEqual(SDP);
    expect(Object.keys(got).sort()).toEqual(['payload', 'senderId', 'type']);

    // 送信元を偽ろうとフレームを細工しても、宛先 16 バイトの後ろは SDP の本体としてしか読まれない
    const frame = encodeTrackerClientMessage({ type: 'relay', targetPeerId: alice.peerId, payload: SDP });
    const forged = new Uint8Array(frame.length + 16);
    forged.set(frame);
    forged.set(Encoding16(bob.peerId), frame.length);
    m.send(forged);
    expect((await m.next((x) => x.type === 'error')).code).toBe('bad-message');
  });

  it('不在の相手・自分自身への relay は黙って捨てる (登録者の問い合わせに使わせない)', async () => {
    const a = await RawClient.open();
    await a.joined(alice);
    const before = a.messages.length;
    a.send({ type: 'relay', targetPeerId: bob.peerId, payload: SDP });
    a.send({ type: 'relay', targetPeerId: alice.peerId, payload: SDP });
    await settle(150);
    expect(a.messages.length).toBe(before);
    expect(a.closed).toBe(false);
  });

  it('不正な中継フレームは拒否する (切り詰め・余り・不正な SDP 種別・不正な UTF-8)', async () => {
    const ok = encodeTrackerClientMessage({ type: 'relay', targetPeerId: bob.peerId, payload: SDP });
    const cases: Array<[string, Uint8Array]> = [
      ['宛先が途中まで', ok.slice(0, 10)],
      ['本文が切り詰め', ok.slice(0, ok.length - 1)],
      ['余りバイト', Uint8Array.of(...ok, 0)],
      ['SDP の種別が範囲外', (() => { const g = ok.slice(); g[1 + 16] = 9; return g; })()],
      ['SDP が不正な UTF-8', (() => { const g = ok.slice(); g[g.length - 1] = 0xff; return g; })()],
    ];
    for (const [name, frame] of cases) {
      const a = await RawClient.open();
      await a.joined(alice);
      a.send(frame);
      expect((await a.next((x) => x.type === 'error')).code, name).toBe('bad-message');
      await a.waitClosed();
    }
  });

  it('ICE candidate も中継でき、null の項目も保たれる', async () => {
    const a = await RawClient.open();
    await a.joined(alice);
    const b = await RawClient.open();
    await b.joined(bob);
    const candidate = { candidate: 'candidate:1 1 udp 2122260223 192.0.2.1 54321 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: null };
    b.send({ type: 'relay', targetPeerId: alice.peerId, payload: { candidate } });
    expect((await a.next((x) => x.type === 'relay')).payload).toEqual({ candidate });
  });
});

describe('トラッカー v3: 資源の上限', () => {
  it('★join のフラッドを頭打ちにする', async () => {
    await stopTracker();
    await startTracker({ rateLimiter: new RateLimiter({ join: { ratePerSec: 0.001, burst: 1 }, relay: { ratePerSec: 1, burst: 1 } }) });
    const c = await RawClient.open();
    await c.joined(alice);
    for (let i = 0; i < 5; i++) c.send(joinFrame(bob, new Uint8Array(32), `127.0.0.1:${port}`));
    expect((await c.next((m) => m.type === 'error')).code).toBe('rate-limited');
  });

  it('同じ送信元アドレスからの同時接続数を制限し、切断したら枠を戻す', async () => {
    await stopTracker();
    await startTracker({ maxConnectionsPerAddress: 2 });
    const a = await RawClient.open();
    const b = await RawClient.open();
    await a.nonce();
    await b.nonce();
    const c = await RawClient.open();
    expect((await c.next((m) => m.type === 'error')).code).toBe('capacity');
    await c.waitClosed();

    a.close();
    await a.waitClosed();
    await settle(50);
    const d = await RawClient.open();
    await d.nonce();
    b.close(); d.close();
  });

  it('登録数の上限を超えたら capacity を返す', async () => {
    await stopTracker();
    await startTracker({ maxSessions: 1 });
    const a = await RawClient.open();
    await a.joined(alice);
    const b = await RawClient.open();
    await b.joinAs(bob);
    expect((await b.next((m) => m.type === 'error')).code).toBe('capacity');
  });

  it('peers は件数を絞り、偏りなく選ぶ', async () => {
    await stopTracker();
    await startTracker({ peersPerJoin: 2 });
    const ids = await Promise.all([1, 2, 3, 4].map(() => NodeIdentity.mine(PARAMS)));
    const clients = [];
    for (const id of ids) {
      const c = await RawClient.open();
      await c.joined(id);
      clients.push(c);
    }
    const seen = new Set<string>();
    for (let i = 0; i < 12; i++) {
      const c = await RawClient.open();
      const peers = await c.joined(alice);
      expect(peers.length).toBe(2);
      for (const p of peers) {
        expect(Object.keys(p)).toEqual(['peerId']);
        seen.add(p.peerId);
      }
      c.close();
      await c.waitClosed();
    }
    expect(seen.size).toBeGreaterThan(2);
  });

  it('ログに peerId も IP アドレスも出さない', async () => {
    const a = await RawClient.open();
    await a.joined(alice);
    const m = await RawClient.open();
    await m.joinAs(alice, {}, mallory);
    await m.next((x) => x.type === 'error');
    for (const line of logs) {
      expect(line).not.toContain(alice.peerId);
      expect(line).not.toContain('127.0.0.1');
    }
  });

  it('停止すると全接続を閉じ、以後は接続を受け付けない', async () => {
    const a = await RawClient.open();
    await a.joined(alice);
    tracker.shutdown();
    await a.waitClosed();
    await expect(RawClient.open()).rejects.toBeTruthy();
    // afterEach の stopTracker が二重停止でも落ちないこと
  });
});

describe('トラッカー v3: クライアント側の拒否の扱い', () => {
  it('SignalingClient は拒否理由のコードを TrackerJoinError で受け取る', async () => {
    await stopTracker();
    await startTracker({ allowedHosts: ['only.example'] });
    const client = new SignalingClient(url, { WebSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket });
    await expect(client.connect({ claim: alice.claim(), identity: alice })).rejects.toMatchObject({ code: 'bad-host' });
    await expect(client.connect({ claim: alice.claim(), identity: alice })).rejects.toBeInstanceOf(TrackerJoinError);
  });
});
