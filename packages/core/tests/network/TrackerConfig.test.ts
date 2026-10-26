import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import {
  parseTrackerUrl,
  TRACKER_URL_MAX_LENGTH,
  createTrackerString,
  parseTrackerString,
  resolveTrackerWebSocketUrl,
} from '../../src/network/TrackerUrl';
import { SignalingClient, TrackerNotConfiguredError } from '../../src/network/SignalingClient';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { OzNode } from '../../src/node/OzNode';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import type { WireNodeClaim } from '../../src/types';
import { Encoding } from '../../src/common/Encoding';
import {
  TRACKER_PROTOCOL_VERSION,
  encodeTrackerServerMessage,
  parseTrackerClientMessage,
  type TrackerServerMessage,
} from '../../src/network/TrackerProtocol';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };

/** 本物の WebSocket の代わり。開く・閉じる・届く を手で起こす */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readyState = 0;
  /** クライアントが送ったフレームを、トラッカーと同じ検証関数で読み戻したもの */
  sent: any[] = [];
  /** 送られた生のフレーム */
  frames: Uint8Array[] = [];
  binaryType = 'blob';
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: ArrayBuffer | string }) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }
  send(data: Uint8Array) {
    // ★ バイナリで送ること (テキストは不可)
    expect(data).toBeInstanceOf(Uint8Array);
    this.frames.push(data);
    this.sent.push(parseTrackerClientMessage(data));
  }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.());
  }
  open() { this.readyState = 1; this.onopen?.(); }
  /** トラッカー側の振る舞い: hello を送り、join が来たら peers を返す */
  handshake(nonce: Uint8Array = new Uint8Array(32).fill(0xab)) {
    this.open();
    this.receive({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce });
    if (this.sent.some((m) => m.type === 'join')) this.receive({ type: 'peers', peers: [] });
  }
  /** オブジェクトは符号化して、Uint8Array はそのまま (壊れたフレームの再現用) 届ける */
  receive(msg: TrackerServerMessage | Uint8Array) {
    const bytes = msg instanceof Uint8Array ? msg : encodeTrackerServerMessage(msg);
    this.onmessage?.({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer });
  }
  static last(): FakeWebSocket { return FakeWebSocket.instances[FakeWebSocket.instances.length - 1]; }
}
const WS = FakeWebSocket as unknown as typeof WebSocket;

let me: NodeIdentity;
beforeAll(async () => {
  me = await NodeIdentity.mine(FAST);
});
const claim = () => ({ claim: me.claim() as WireNodeClaim, identity: me });

afterEach(() => {
  FakeWebSocket.instances = [];
  vi.useRealTimers();
});

describe('トラッカー URL の検証', () => {
  it('wss:// を受け付け、パスを省略したら /ws にする', () => {
    expect(parseTrackerUrl('wss://tracker.example.org')).toEqual({ ok: true, url: 'wss://tracker.example.org/ws' });
    expect(parseTrackerUrl('  wss://tracker.example.org/  ')).toEqual({ ok: true, url: 'wss://tracker.example.org/ws' });
    expect(parseTrackerUrl('wss://tracker.example.org:8443/signal')).toEqual({ ok: true, url: 'wss://tracker.example.org:8443/signal' });
  });

  it('平文の ws:// は自分の端末 (localhost / 127.0.0.0/8 / ::1) に限る', () => {
    expect(parseTrackerUrl('ws://localhost:3000').ok).toBe(true);
    expect(parseTrackerUrl('ws://127.0.0.1:3000/ws').ok).toBe(true);
    expect(parseTrackerUrl('ws://127.1.2.3/ws').ok).toBe(true);
    expect(parseTrackerUrl('ws://[::1]:3000/ws').ok).toBe(true);

    for (const bad of [
      'ws://tracker.example.org/ws',
      'ws://192.168.1.10:3000/ws',
      'ws://localhost.evil.example/ws',
      'ws://127.0.0.1.evil.example/ws',
      'ws://[::ffff:8.8.8.8]/ws',
    ]) {
      expect(parseTrackerUrl(bad), bad).toEqual({ ok: false, reason: 'insecure' });
    }
  });

  it('ws/wss 以外の方式は拒否する', () => {
    for (const bad of ['https://tracker.example.org', 'http://localhost:3000', 'file:///etc/passwd', 'javascript:alert(1)']) {
      expect(parseTrackerUrl(bad).ok, bad).toBe(false);
    }
  });

  it('認証情報・クエリ・フラグメントを含む URL は拒否する', () => {
    expect(parseTrackerUrl('wss://user:pw@tracker.example.org/ws')).toEqual({ ok: false, reason: 'credentials' });
    expect(parseTrackerUrl('wss://user@tracker.example.org/ws')).toEqual({ ok: false, reason: 'credentials' });
    expect(parseTrackerUrl('wss://tracker.example.org/ws?id=123')).toEqual({ ok: false, reason: 'query' });
    expect(parseTrackerUrl('wss://tracker.example.org/ws?')).toEqual({ ok: false, reason: 'query' });
    expect(parseTrackerUrl('wss://tracker.example.org/ws#x')).toEqual({ ok: false, reason: 'fragment' });
    expect(parseTrackerUrl('wss://tracker.example.org/ws#')).toEqual({ ok: false, reason: 'fragment' });
  });

  it('空・壊れた値・長すぎる値は拒否する', () => {
    expect(parseTrackerUrl('')).toEqual({ ok: false, reason: 'empty' });
    expect(parseTrackerUrl('   ')).toEqual({ ok: false, reason: 'empty' });
    expect(parseTrackerUrl('tracker.example.org')).toEqual({ ok: false, reason: 'invalid' });
    expect(parseTrackerUrl(undefined as unknown as string)).toEqual({ ok: false, reason: 'empty' });
    expect(parseTrackerUrl('wss://t.example/' + 'a'.repeat(TRACKER_URL_MAX_LENGTH))).toEqual({ ok: false, reason: 'too-long' });
  });

  it('ポート開放トラッカー用の oz-tracker:... トークンを生成・検証・展開でき、改ざんは拒否する', async () => {
    const token = createTrackerString({ host: '203.0.113.42', port: 18787 });
    expect(token.startsWith('oz-tracker:')).toBe(true);
    // トークン文字列や単純 Base64 デコード結果に生 IP やポート番号が露出しない
    expect(token).not.toContain('203.0.113.42');
    expect(token).not.toContain('18787');
    const rawDecoded = Buffer.from(token.slice('oz-tracker:'.length), 'base64url').toString('utf8');
    expect(rawDecoded).not.toContain('203.0.113.42');

    expect(parseTrackerString(token)).toEqual({
      host: '203.0.113.42',
      port: 18787,
      tls: false,
      path: '/ws',
    });
    expect(parseTrackerUrl(token)).toEqual({ ok: true, url: token });
    expect(resolveTrackerWebSocketUrl(token)).toBe('ws://203.0.113.42:18787/ws');

    // 1 文字でも改ざんされたら拒否する
    const flipped = token.slice(0, -2) + (token.endsWith('A') ? 'B' : 'A') + token.slice(-1);
    expect(parseTrackerString(flipped)).toBeNull();
    expect(parseTrackerUrl(flipped)).toEqual({ ok: false, reason: 'invalid' });

    // SignalingClient は url プロパティには oz-tracker:... を保持したまま、接続時のみ展開先 WebSocket に繋ぐ
    const client = new SignalingClient(token, { WebSocketImpl: WS });
    expect(client.url).toBe(token);
    const p = client.connect(claim());
    const ws = FakeWebSocket.last();
    expect(ws.url).toBe('ws://203.0.113.42:18787/ws');
    ws.handshake();
    await p;
    expect(ws.sent[0]).toMatchObject({ type: 'join', host: '203.0.113.42:18787' });
  });
});

describe('SignalingClient: 接続先を推測しない', () => {
  it('URL が未設定なら接続を試みずに失敗する', async () => {
    const client = new SignalingClient(null, { WebSocketImpl: WS });
    expect(client.url).toBeNull();
    await expect(client.connect(claim())).rejects.toBeInstanceOf(TrackerNotConfiguredError);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it('不正な URL は生成時・変更時ともに例外にし、以前の設定を残す', () => {
    expect(() => new SignalingClient('ws://tracker.example.org/ws', { WebSocketImpl: WS })).toThrow(/insecure/);
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    expect(() => client.setUrl('http://b.example')).toThrow();
    expect(client.url).toBe('wss://a.example/ws');
  });

  it('設定した URL にだけ接続し、自分の claim で登録する', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    const p = client.connect(claim());
    const ws = FakeWebSocket.last();
    expect(ws.url).toBe('wss://a.example/ws');
    ws.handshake();
    await p;
    expect(client.isConnected).toBe(true);
    expect(ws.sent).toEqual([expect.objectContaining({ type: 'join', peerId: me.peerId, host: 'a.example' })]);
    // 購読ゾーンや位置は送らない
    expect(ws.sent[0]).not.toHaveProperty('zones');
    expect(ws.sent[0]).not.toHaveProperty('position');
  });

  it('接続中に重ねて connect しても、ソケットは 1 本だけ (同じ ID を二重登録しない)', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    const p1 = client.connect(claim());
    const p2 = client.connect(claim());
    expect(FakeWebSocket.instances).toHaveLength(1);
    FakeWebSocket.last().handshake();
    await Promise.all([p1, p2]);
    await client.connect(claim()); // 接続済みなら何もしない
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.last().sent).toHaveLength(1);
  });

  it('接続先を変えたら古い接続を閉じ、古いトラッカーからの通知は無視する', async () => {
    const client = new SignalingClient('wss://old.example', { WebSocketImpl: WS });
    const peers = vi.fn();
    client.on('peers', peers);
    const p = client.connect(claim());
    const old = FakeWebSocket.last();
    old.handshake();
    await p;

    client.setUrl('wss://new.example');
    expect(old.readyState).toBe(3);
    expect(client.isConnected).toBe(false);
    old.receive({ type: 'peers', peers: [{ peerId: 'c'.repeat(32) }] });
    expect(peers).not.toHaveBeenCalledWith([{ peerId: 'c'.repeat(32) }]);

    const p2 = client.connect(claim());
    const fresh = FakeWebSocket.last();
    expect(fresh.url).toBe('wss://new.example/ws');
    fresh.handshake();
    await p2;
    fresh.receive({ type: 'peers', peers: [{ peerId: 'd'.repeat(32) }] });
    expect(peers).toHaveBeenCalledWith([{ peerId: 'd'.repeat(32) }]);
  });

  it('接続待ちの間に URL を変えたら、その接続は失敗として終わる', async () => {
    const client = new SignalingClient('wss://old.example', { WebSocketImpl: WS });
    const p = client.connect(claim());
    client.setUrl('wss://new.example');
    await expect(p).rejects.toThrow();
    // 遅れて開いても登録しない
    FakeWebSocket.instances[0].handshake();
    expect(FakeWebSocket.instances[0].sent).toHaveLength(0);
  });

  it('開く前に閉じられたら失敗する。応答が無ければ時間切れで失敗する', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS, connectTimeoutMs: 50 });
    const p = client.connect(claim());
    FakeWebSocket.last().close();
    await expect(p).rejects.toThrow(/closed/);

    vi.useFakeTimers();
    const p2 = client.connect(claim());
    const check = expect(p2).rejects.toThrow(/timeout/);
    await vi.advanceTimersByTimeAsync(60);
    await check;
    expect(FakeWebSocket.last().readyState).toBe(3);
  });
});

describe('PeerManager: トラッカーへの再試行', () => {
  let identity: NodeIdentity;
  beforeAll(async () => {
    identity = await NodeIdentity.mine(FAST);
  });

  it('起動時にトラッカーへ届かなくても、後で再試行する', async () => {
    vi.useFakeTimers();
    const signaling = {
      connect: vi.fn().mockRejectedValueOnce(new Error('unreachable')).mockResolvedValue(undefined),
      disconnect: vi.fn(),
      sendRelay: vi.fn(),
      on: vi.fn(),
      isConnected: false,
    };
    const pm = new PeerManager(identity, new MessageDispatcher(), signaling as any);
    await expect(pm.start()).rejects.toThrow('unreachable');
    expect(signaling.connect).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(signaling.connect).toHaveBeenCalledTimes(2);
    // 再接続できたら、しばらくして切り離す (トラッカーに見られる期間を短く保つ)
    await vi.advanceTimersByTimeAsync(15_000);
    expect(signaling.disconnect).toHaveBeenCalled();
    pm.stop();
  });

  it('停止後は再試行しない', async () => {
    vi.useFakeTimers();
    const signaling = {
      connect: vi.fn().mockRejectedValue(new TrackerNotConfiguredError()),
      disconnect: vi.fn(),
      sendRelay: vi.fn(),
      on: vi.fn(),
      isConnected: false,
    };
    const pm = new PeerManager(identity, new MessageDispatcher(), signaling as any);
    await expect(pm.start()).rejects.toBeInstanceOf(TrackerNotConfiguredError);
    pm.stop();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(signaling.connect).toHaveBeenCalledTimes(1);
    await pm.reconnectTracker();
    expect(signaling.connect).toHaveBeenCalledTimes(1);
  });
});

describe('OzNode: トラッカーの設定', () => {
  const makeNode = async (signalingClient: SignalingClient) => {
    const db = new IndexedDBStore(`tracker-${Math.random()}`);
    await db.init();
    return OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db,
      signalingClient,
      passphrase: 'test-passphrase',
      vaultParams: VAULT_PARAMS_FAST,
      autoStart: false,
    });
  };

  it('不正なトラッカー URL では起動しない', async () => {
    const db = new IndexedDBStore(`tracker-bad-${Math.random()}`);
    await db.init();
    await expect(OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db,
      trackerUrl: 'ws://tracker.example.org/ws',
      passphrase: 'test-passphrase',
      vaultParams: VAULT_PARAMS_FAST,
      autoStart: false,
    })).rejects.toThrow(/insecure/);
  });

  it('未設定でも起動でき、後から設定するとそのトラッカーへ接続する', async () => {
    const client = new SignalingClient(null, { WebSocketImpl: WS });
    const node = await makeNode(client);
    await node.start();
    expect(node.trackerUrl).toBeNull();
    expect(FakeWebSocket.instances).toHaveLength(0);

    const p = node.setTrackerUrl('wss://tracker.example.org');
    expect(node.trackerUrl).toBe('wss://tracker.example.org/ws');
    const ws = FakeWebSocket.last();
    ws.handshake();
    await p;
    expect(ws.sent[0]).toMatchObject({ type: 'join', peerId: node.peerId });

    // 不正な URL は拒否し、設定は変えない
    await expect(node.setTrackerUrl('ws://tracker.example.org')).rejects.toThrow(/insecure/);
    expect(node.trackerUrl).toBe('wss://tracker.example.org/ws');

    // 未設定に戻すと接続を切る
    await node.setTrackerUrl(null);
    expect(node.trackerUrl).toBeNull();
    expect(ws.readyState).toBe(3);
    await node.stop();
  });

  it('停止中のノードでは設定を保存するだけで接続しない', async () => {
    const client = new SignalingClient(null, { WebSocketImpl: WS });
    const node = await makeNode(client);
    await node.setTrackerUrl('wss://tracker.example.org');
    expect(FakeWebSocket.instances).toHaveLength(0);
    await node.stop();
    await expect(node.setTrackerUrl('wss://other.example')).rejects.toThrow(/stopped/);
  });
});

describe('トラッカーへの登録: 所有証明 (v3)', () => {
  const nonce0 = new Uint8Array(32).fill(0xcd);
  const nonceHex = Encoding.toHex(nonce0);

  it('hello の nonce と接続先ホストに署名した join を送り、トラッカー側の検証を通る', async () => {
    const client = new SignalingClient('wss://Tracker.Example.org:8443', { WebSocketImpl: WS });
    const p = client.connect(claim());
    const ws = FakeWebSocket.last();
    ws.open();
    expect(ws.sent).toHaveLength(0); // hello を受け取るまで何も送らない
    ws.receive({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: nonce0 });
    expect(ws.binaryType).toBe('arraybuffer');
    const join = ws.sent[0];
    expect(join).toMatchObject({ type: 'join', v: TRACKER_PROTOCOL_VERSION, peerId: me.peerId, host: 'tracker.example.org:8443', powCounter: me.powCounter });
    expect(Object.keys(join).sort()).toEqual(['host', 'peerId', 'powCounter', 'pubkey', 'sig', 'type', 'v']);
    expect(NodeIdentity.verifyTrackerJoin(
      { peerId: join.peerId, pubkey: join.pubkey, powCounter: join.powCounter },
      nonce0, join.host, join.sig, FAST,
    )).toBe(true);
    // 別の nonce / ホストでは通らない (署名が nonce と host に束縛されている)
    expect(NodeIdentity.verifyTrackerJoin(me.claim(), new Uint8Array(32).fill(0xce), join.host, join.sig, FAST)).toBe(false);
    expect(NodeIdentity.verifyTrackerJoin(me.claim(), nonce0, 'evil.example', join.sig, FAST)).toBe(false);
    ws.receive({ type: 'peers', peers: [] });
    await p;
  });

  it('署名は別の nonce・別のホスト・別の ID では検証を通らない', () => {
    const nonce = Encoding.fromHex(nonceHex);
    const sig = me.signTrackerJoin(nonce, 'a.example');
    const c = me.claim();
    expect(NodeIdentity.verifyTrackerJoin(c, nonce, 'a.example', sig, FAST)).toBe(true);
    expect(NodeIdentity.verifyTrackerJoin(c, nonce, 'A.EXAMPLE', sig, FAST)).toBe(true); // ホストは大小無視
    expect(NodeIdentity.verifyTrackerJoin(c, Encoding.fromHex('ce'.repeat(32)), 'a.example', sig, FAST)).toBe(false);
    expect(NodeIdentity.verifyTrackerJoin(c, nonce, 'b.example', sig, FAST)).toBe(false);
    const flipped = sig.slice();
    flipped[0] ^= 1;
    expect(NodeIdentity.verifyTrackerJoin(c, nonce, 'a.example', flipped, FAST)).toBe(false);
    expect(NodeIdentity.verifyTrackerJoin(c, nonce.slice(0, 31), 'a.example', sig, FAST)).toBe(false);
    expect(NodeIdentity.verifyTrackerJoin(c, nonce, '', sig, FAST)).toBe(false);
  });

  it('P2P の JOIN 署名とトラッカー登録の署名は互いに流用できない (ドメイン分離)', async () => {
    const nonce = Encoding.fromHex(nonceHex);
    const p2p = me.signClaim(nonce, { verifierId: 'a.example', signerFingerprint: '', verifierFingerprint: '' });
    expect(NodeIdentity.verifyTrackerJoin(me.claim(), nonce, 'a.example', p2p.signature, FAST)).toBe(false);
  });

  it('公開情報 (peerId・pubkey・powCounter) だけでは他人として登録できない', async () => {
    const other = await NodeIdentity.mine(FAST);
    const nonce = Encoding.fromHex(nonceHex);
    // 攻撃者は自分の鍵で署名し、他人の claim を添える
    const sig = me.signTrackerJoin(nonce, 'a.example');
    expect(NodeIdentity.verifyTrackerJoin(other.claim(), nonce, 'a.example', sig, FAST)).toBe(false);
  });

  it('トラッカーが登録を拒否したら、理由のコード付きで失敗する', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    const p = client.connect(claim());
    const ws = FakeWebSocket.last();
    ws.open();
    ws.receive({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: nonce0 });
    ws.receive({ type: 'error', code: 'bad-signature' });
    await expect(p).rejects.toMatchObject({ name: 'TrackerJoinError', code: 'bad-signature' });
    expect(ws.readyState).toBe(3);
  });

  it('対応していない版・hello 以外の最初のメッセージ・壊れた hello では登録しない', async () => {
    for (const first of [
      { type: 'hello', v: 2, nonce: nonce0 } as TrackerServerMessage,
      { type: 'peers', peers: [] } as TrackerServerMessage,
      new Uint8Array([0x01, TRACKER_PROTOCOL_VERSION, 1, 2, 3]), // 切り詰めた hello
    ]) {
      const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS, connectTimeoutMs: 50 });
      vi.useFakeTimers();
      const p = client.connect(claim());
      const check = expect(p).rejects.toThrow();
      const ws = FakeWebSocket.last();
      ws.open();
      ws.receive(first);
      await vi.advanceTimersByTimeAsync(60);
      await check;
      expect(ws.sent.filter((m) => m.type === 'join')).toHaveLength(0);
      vi.useRealTimers();
    }
  });

  it('登録前に届いた relay は捨て、登録後のものだけを渡す', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    const relay = vi.fn();
    client.on('relay', relay);
    const p = client.connect(claim());
    const ws = FakeWebSocket.last();
    ws.open();
    ws.receive({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: nonce0 });
    const sdp = (text: string) => ({ sdp: { type: 'offer', sdp: text } });
    ws.receive({ type: 'relay', senderId: 'e'.repeat(32), payload: sdp('early') });
    ws.receive({ type: 'peers', peers: [] });
    await p;
    ws.receive({ type: 'relay', senderId: 'e'.repeat(32), payload: sdp('late') });
    ws.receive(new Uint8Array([0x04, 1, 2, 3])); // 壊れた中継は捨てる
    expect(relay.mock.calls).toEqual([['e'.repeat(32), sdp('late')]]);
  });

  it('署名できない identity では接続しない', async () => {
    const client = new SignalingClient('wss://a.example', { WebSocketImpl: WS });
    await expect(client.connect({ claim: me.claim() as WireNodeClaim })).rejects.toThrow(/identity/);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});
