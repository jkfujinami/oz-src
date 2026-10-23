// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { render, screen, cleanup, act, waitFor } from '@testing-library/react';
import sodium from 'libsodium-wrappers-sumo';
import 'fake-indexeddb/auto';

import BoardView from '../src/components/BoardView';
import ThreadView from '../src/components/ThreadView';
import { P2PContextForTest } from '../src/providers/P2PProvider';
import {
  BoardOrchestrator,
  ThreadOrchestrator,
  GossipRouter,
  RecentBuffer,
  MessageDispatcher,
  CryptoEngine,
  Identity,
  KeyManager,
  PacketBuilder,
  PoWEngine,
  WireType,
  DandelionRouter,
  type IPeerManager,
  type IPoWEngine,
  type IKeyManager,
} from '@oz/core';

const ME = 'aa'.repeat(16);
const PEER = 'bb'.repeat(16);
const BOARD_ID = 'vip';
let BOARD_KEY: Uint8Array;

class FakeStore {
  async getPosts() { return []; }
  async getThreads() { return []; }
  async save() {}
  async touchThread() {}
}

class FakePeerManager {
  public myPeerId = ME;
  public myPosition = 0.5;
  public peers = new Map();
  public degree = 1;
  private listeners = new Map<string, Array<(...args: any[]) => void>>();

  constructor() {
    this.peers.set(PEER, { peerId: PEER, isConnected: true, isVerified: true });
  }
  sendMessage() {}
  on(event: string, cb: any) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event)!.push(cb);
  }
  off(event: string, cb: any) {
    const list = this.listeners.get(event) || [];
    this.listeners.set(event, list.filter(l => l !== cb));
  }
}

const syncPowEngine: IPoWEngine = {
  compute: (h) => PoWEngine.compute(h),
};

const fakeKeyMgr: IKeyManager = {
  deriveThreadKey: KeyManager.deriveThreadKey,
};

function setupHarness() {
  const pm = new FakePeerManager() as unknown as IPeerManager;
  const dispatcher = new MessageDispatcher();
  const db = new FakeStore();
  const dandelion = new DandelionRouter(pm);
  // 送信は検証の対象外 (受信して描画されることだけを見る)。回路は送信を受け付けるだけのスタブ
  const circuit: any = { onExit: () => {}, send: async () => true, start: () => {}, stop: () => {} };
  const router = new GossipRouter(pm, dispatcher, dandelion, circuit, RecentBuffer.forRole('client'));
  const cryptoEng = new CryptoEngine();
  const identity = new Identity();

  const boardOrchestrator = new BoardOrchestrator(pm, db as any, router, cryptoEng, syncPowEngine, identity);
  const threadOrchestrator = new ThreadOrchestrator(pm, db as any, router, cryptoEng, syncPowEngine, identity, fakeKeyMgr);

  return {
    ctx: {
      node: null,
      boardOrchestrator,
      threadOrchestrator,
      pm: pm as any,
      identity,
      db: null,
      isReady: true,
      lockState: 'ready',
      unlockError: null,
      unlock: async () => {},
      resetAll: async () => {},
      panicWipe: async () => {},
      lock: async () => {},
    },
    dispatcher,
    router,
    db,
    boardOrchestrator,
    threadOrchestrator,
  };
}

function Wrap({ value, children }: { value: any; children: React.ReactNode }) {
  return <P2PContextForTest.Provider value={value}>{children}</P2PContextForTest.Provider>;
}

beforeAll(async () => {
  await sodium.ready;
  BOARD_KEY = KeyManager.cryptoHash(
    new TextEncoder().encode('OZ_LITE_VIP_DEFAULT_SEED'),
  ).slice(0, 32);

  for (const m of ['log', 'warn', 'debug', 'error'] as const) {
    vi.spyOn(console, m).mockImplementation(() => {});
  }
  window.location.hash = `#board=${BOARD_ID}`;
});

afterEach(() => {
  cleanup();
});

describe('DesktopLiveRender: ネットワークから届いたパケットが DOM に描画されることの保証', () => {
  it('★Guard からの追いつき (flood しない配信) で届いたスレッドが DOM に現れる', async () => {
    const { ctx, router } = setupHarness();
    await act(async () => {
      render(
        <Wrap value={ctx}>
          <BoardView boardId={BOARD_ID} />
        </Wrap>,
      );
    });
    expect(screen.queryByText('追いつきで受信したスレッド')).toBeNull();

    const packet = await PacketBuilder.build({
      content: '追いつきで受信したスレッド', key: BOARD_KEY, identity: new Identity(), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: BOARD_ID, threadId: 'thread-catchup-001', postType: 1,
    });
    await act(async () => {
      expect(router.deliverCatchup(packet)).toBe(true);
      await new Promise((r) => setTimeout(r, 60));
    });
    await waitFor(() => {
      expect(screen.getByText('追いつきで受信したスレッド')).toBeTruthy();
    });
  });

  it('★板を開く前に追いつきで届いていたスレッドも、板を開いたときに DOM に現れる (直近に見た投稿の流し込み)', async () => {
    const { ctx, router } = setupHarness();
    const packet = await PacketBuilder.build({
      content: '先に届いていたスレッド', key: BOARD_KEY, identity: new Identity(), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: BOARD_ID, threadId: 'thread-catchup-002', postType: 1,
    });
    router.deliverCatchup(packet); // まだ誰も板を開いていない
    await act(async () => {
      render(
        <Wrap value={ctx}>
          <BoardView boardId={BOARD_ID} />
        </Wrap>,
      );
    });
    await waitFor(() => {
      expect(screen.getByText('先に届いていたスレッド')).toBeTruthy();
    });
  });

  it('★Gossip で流れてきた新着スレッドがリアルタイムに DOM に反映される', async () => {
    const { ctx, dispatcher } = setupHarness();

    // 板の鍵の解決は非同期なので、描画に伴う effect の完了まで act の中で待つ
    await act(async () => {
      render(
        <Wrap value={ctx}>
          <BoardView boardId={BOARD_ID} />
        </Wrap>,
      );
    });

    const packet = await PacketBuilder.build({
      content: 'Gossip生中継スレッド', key: BOARD_KEY, identity: new Identity(), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: BOARD_ID, threadId: 'thread-gossip-live', postType: 1,
    });

    await act(async () => {
      dispatcher.dispatch(PEER, WireType.GOSSIP, { packet });
      await new Promise((r) => setTimeout(r, 50));
    });

    await waitFor(() => {
      expect(screen.getByText('Gossip生中継スレッド')).toBeTruthy();
    });
  });

  it('★ThreadView において、後から届いたレスがリアルタイムに DOM に積み上がる', async () => {
    const { ctx, dispatcher } = setupHarness();
    const threadId = 'thread-live-target';
    const threadKey = KeyManager.deriveThreadKey(BOARD_KEY, threadId);

    // 板の鍵の解決は非同期なので、描画に伴う effect の完了まで act の中で待つ
    await act(async () => {
      render(
        <Wrap value={ctx}>
          <ThreadView boardId={BOARD_ID} threadId={threadId} />
        </Wrap>,
      );
    });

    const postPacket = await PacketBuilder.build({
      content: 'リアルタイム着信レス: こんにちは', key: threadKey, identity: new Identity(), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: BOARD_ID, threadId: threadId, postType: 0,
    });

    await act(async () => {
      dispatcher.dispatch(PEER, WireType.GOSSIP, { packet: postPacket });
      await new Promise((r) => setTimeout(r, 50));
    });

    await waitFor(() => {
      expect(screen.getByText(/リアルタイム着信レス/)).toBeTruthy();
    });
  });
});
