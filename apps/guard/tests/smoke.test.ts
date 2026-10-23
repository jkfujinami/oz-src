/**
 * 実物の WebRTC (node-datachannel) で、トラッカー・Guard・クライアント 2 台を loopback でつなぐ結合テスト。
 * core のテストは偽の WebRTC なので、これが本物の通信での初めての確認になる。
 *
 *   OZ_SKIP_WEBRTC_SMOKE=1 で飛ばせる (node-datachannel が動かない環境用)。
 *
 * 確かめること:
 *   1. Guard が再起動しても同じ peerId で立ち上がる (スナップショット)
 *   2. クライアントが Guard につながり、JOIN (本人確認) を通る
 *   3. クライアントが信頼 Guard を 1 ホップ目に固定する
 *   4. 投稿が Guard 経由で別のクライアントに届く (Guard の追いつきバッファにも載る)
 *   5. 再接続したクライアントが Guard の追いつきで取り逃した分を受け取る
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  OzNode, IndexedDBStore, KeyManager, VAULT_PARAMS_FAST, signGuardList, sodium, sodiumReady,
} from '@oz/core';
import { StunServer, TrackerServer } from '@oz/tracker';
import { startGuard, type GuardHandle } from '../src/GuardApp';
import type { GuardConfig } from '../src/config';

const SKIP = process.env.OZ_SKIP_WEBRTC_SMOKE === '1';
const t0 = Date.now();
const lap = (what: string) => console.log(`[smoke +${((Date.now() - t0) / 1000).toFixed(1)}s] ${what}`);

async function until(what: string, cond: () => boolean | Promise<boolean>, timeoutMs: number, stepMs = 100): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  throw new Error(`timeout (${timeoutMs}ms) waiting for: ${what}`);
}

describe.skipIf(SKIP)('Guard の結合テスト (本物の WebRTC / loopback)', () => {
  let http: Server;
  let tracker: TrackerServer;
  let trackerUrl: string;
  // ★ STUN もトラッカー側 (プロセス内) に立てる。Google などの外部 STUN には出ない
  let stun: StunServer;
  let iceServers: string[];
  let dataDir: string;
  const stoppers: Array<() => Promise<void>> = [];

  const maintainer: { pk: Uint8Array; sk: Uint8Array } = { pk: new Uint8Array(0), sk: new Uint8Array(0) };

  beforeAll(async () => {
    await sodiumReady;
    const kp = sodium.crypto_sign_keypair();
    maintainer.pk = kp.publicKey;
    maintainer.sk = kp.privateKey;

    http = createServer();
    tracker = new TrackerServer(http, { exclusiveUpgrade: true });
    await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
    stun = new StunServer();
    iceServers = [`stun:127.0.0.1:${await stun.listen(0, '127.0.0.1')}`];
    trackerUrl = `ws://127.0.0.1:${(http.address() as AddressInfo).port}/ws`;
    dataDir = join(mkdtempSync(join(tmpdir(), 'oz-guard-smoke-')), 'guard');
  });

  afterAll(async () => {
    for (const stop of stoppers.reverse()) await stop().catch(() => undefined);
    tracker?.shutdown();
    await stun?.close();
    await new Promise<void>((r) => http?.close(() => r()));
    rmSync(join(dataDir, '..'), { recursive: true, force: true });
  });

  const baseConfig = (): GuardConfig => ({
    trackerUrl,
    iceServers,
    dataDir,
    passphrase: 'smoke-test-passphrase',
    trust: null,
    storageSlots: 1,
    snapshotIntervalMs: 60_000,
  });
  // ★ テスト専用: KDF と保管の PoW だけ軽くする (網の挙動は本番と同じ)
  const fast = { vaultParams: VAULT_PARAMS_FAST, storage: { defaultSlots: 1, slotEffort: 1, chunkEffort: 1 } };

  it('Guard は再起動しても同じ peerId で、信頼リストに載る', async () => {
    const quiet = { print: () => undefined };
    const first = await startGuard(baseConfig(), { ...quiet, nodeOverrides: fast });
    expect(first.createdIdentity).toBe(true);
    const peerId = first.node.peerId;
    lap(`guard 初回起動 peerId=${peerId.slice(0, 8)}...`);
    await first.stop();

    // 署名つきの Guard リスト (メンテナ 1 人)
    const now = Date.now();
    const list = signGuardList(
      { version: 1, issuedAt: now, expiresAt: now + 30 * 24 * 3600_000, guards: [first.guardString], revoked: [] },
      maintainer.sk,
    );
    const lines: string[] = [];
    guard = await startGuard(
      { ...baseConfig(), trust: { maintainerKeys: { threshold: 1, keys: [maintainer.pk] }, guardList: list } },
      { print: (l) => lines.push(l), nodeOverrides: fast },
    );
    stoppers.push(() => guard.stop());
    listText = list;
    expect(guard.createdIdentity).toBe(false);
    expect(guard.node.peerId).toBe(peerId);
    expect(guard.node.guards.hasUsableList).toBe(true);
    expect(guard.node.guards.isTrustedPeerId(peerId)).toBe(true);
    expect(lines.join('\n')).toContain(peerId);
    expect(lines.join('\n')).toContain('リストに載っています');
    lap('guard 再起動 (同じ peerId, 信頼リスト読み込み済み)');
  }, 60_000);

  let guard: GuardHandle;
  let listText: string;

  async function makeClient(name: string, db?: IndexedDBStore): Promise<OzNode> {
    const store = db ?? new IndexedDBStore(`Client_${name}`);
    if (!db) await store.init();
    const node = await OzNode.create({
      db: store,
      passphrase: `${name}-pw`,
      vaultParams: VAULT_PARAMS_FAST,
      storage: { slotEffort: 1, chunkEffort: 1 },
      trackerUrl,
      iceServers,
      trust: { maintainerKeys: { threshold: 1, keys: [maintainer.pk] }, guardList: listText },
      autoStart: true,
    });
    stoppers.push(() => node.stop());
    return node;
  }

  it('クライアント 3 台が Guard につながり、投稿が届き、再接続で追いつく', async () => {
    const boardId = 'smoke';
    const boardKey = KeyManager.cryptoHash(new TextEncoder().encode('OZ_GUARD_SMOKE_BOARD')).slice(0, 32);
    const guardId = guard.node.peerId;

    const alice = await makeClient('alice');
    const bobDb = new IndexedDBStore('Client_bob');
    await bobDb.init();
    let bob = await makeClient('bob', bobDb);
    // ★ 3 台目 (carol) は M1 の役: Guard の隣人が alice 1 人だけだと回路が組めず、投稿は fail-closed で捨てられる
    //   (bob が留守の間の投稿に必要。これは正しい挙動)
    const carol = await makeClient('carol');
    lap('クライアント 3 台を起動');

    // 2. Guard 側で JOIN 検証済みのクライアントが 3 台
    await until('guard sees 3 verified clients', () => guard.counts().clients >= 3, 30_000);
    lap(`guard が検証済みクライアント ${guard.counts().clients} 台を確認`);
    expect(guard.node.degree).toBeGreaterThanOrEqual(2);

    // 3. 1 ホップ目に信頼 Guard を固定している
    await until('clients pin the guard', () =>
      [alice, bob, carol].every((c) => c.guardStatus.mode === 'trusted' && c.guardStatus.guardId === guardId), 30_000);
    lap('3 台とも Guard を 1 ホップ目に固定 (mode=trusted)');
    expect(alice.peerManager.isTrustedGuard(guardId)).toBe(true);
    // ★ WebRTC の ICE がプロセス内のトラッカー STUN に問い合わせた (外部の STUN には出ていない)
    expect(stun.takeCounts().responded).toBeGreaterThan(0);

    // 4. alice の投稿が bob に届く。Guard のバッファにも載る
    for (const n of [alice, bob, carol]) n.boardOrchestrator.activate(boardId, boardKey);
    const title1 = 'smoke: 最初のスレ (alice)';
    const before = guard.node.recent.size;
    const posted = Date.now();
    await alice.boardOrchestrator.submitThread(boardId, boardKey, title1);
    const has = (n: OzNode, title: string) => n.boardOrchestrator.getThreads().some((t) => t.content === title);
    await until('bob receives thread 1', () => has(bob, title1), 30_000);
    lap(`投稿が bob に到達 (${Date.now() - posted}ms)`);
    expect(guard.node.recent.size).toBeGreaterThan(before);

    // 5. bob を止める → alice が投稿 → bob が (同じ DB で) 戻る → Guard の追いつきで受け取る
    await bob.stop();
    await until('carol still connected', () => carol.guardStatus.mode === 'trusted', 5_000);
    lap('bob を停止');
    await until('guard drops bob', () => guard.counts().clients <= 2, 30_000);
    const title2 = 'smoke: bob が留守の間のスレ (alice)';
    await alice.boardOrchestrator.submitThread(boardId, boardKey, title2);
    await until('guard buffers thread 2', () => guard.node.recent.size >= before + 2, 30_000);
    // Guard が CATCHUP_REQ を受けたことを数える (追いつきが本当に Guard 経由かの確認)
    const server = guard.node.catchupServer as unknown as { handleReq: (peerId: string, msg: unknown) => void };
    const orig = server.handleReq.bind(server);
    let catchupRequests = 0;
    server.handleReq = (peerId, msg) => {
      catchupRequests++;
      orig(peerId, msg);
    };
    bob = await makeClient('bob', bobDb);
    bob.boardOrchestrator.activate(boardId, boardKey);
    const back = Date.now();
    await until('bob catches up thread 2', () => has(bob, title2), 40_000);
    lap(`bob が再接続して追いつき (${Date.now() - back}ms)`);
    expect(catchupRequests).toBeGreaterThanOrEqual(1);
    expect(has(bob, title1)).toBe(true);
  }, 120_000);
});
