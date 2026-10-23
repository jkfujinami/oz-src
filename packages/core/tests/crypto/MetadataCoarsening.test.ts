import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { fakePowEngine } from '../helpers/postFixtures';
import { Identity } from '../../src/crypto/Identity';
import { CryptoUtils } from '../../src/common/CryptoUtils';
import { Heartbeat } from '../../src/network/Heartbeat';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';

describe('網に出るメタデータの粗粒度化 (A5)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('ヘッダの時刻と署名層の created_at は分単位に丸められる', async () => {
    const key = sodium.randombytes_buf(32);
    const engine = new CryptoEngine();
    const packet = await PacketBuilder.build({
      content: 'x', key, identity: new Identity(), cryptoEngine: engine, powEngine: fakePowEngine,
      boardId: 'b', threadId: 't', now: Date.UTC(2026, 9, 14, 12, 34, 56, 789),
    });
    expect(packet.timestamp % 60_000).toBe(0);
    expect(packet.timestamp).toBe(Date.UTC(2026, 9, 14, 12, 34));
    const post = await PacketBuilder.verifyAndDecrypt(packet, key, { kind: 'reply', boardId: 'b', threadId: 't' }, engine);
    expect(post!.created_at).toBe(packet.timestamp);
  });

  it('ping に時計の値を載せず、自分が送っていない pong は無視する', () => {
    const sent: Array<{ type: number; payload: any }> = [];
    const peer: any = { peerId: 'p'.repeat(32), isConnected: true, rtt: -1 };
    const pm: any = {
      peers: new Map([[peer.peerId, peer]]),
      sendMessage: (_id: string, type: number, payload: any) => sent.push({ type, payload }),
    };
    const dispatcher = new MessageDispatcher();
    const hb = new Heartbeat(pm, dispatcher);

    (hb as any).pingAll();
    const ping = sent.find(s => s.type === WireType.PING)!;
    // 送ったのは時計の値ではなく 32bit の乱数
    expect(Math.abs(ping.payload.nonce - Date.now())).toBeGreaterThan(1e9);
    expect(ping.payload.nonce).toBeLessThan(2 ** 32);

    dispatcher.dispatch(peer.peerId, WireType.PONG, { nonce: 12345 });
    expect(peer.rtt).toBe(-1);
    dispatcher.dispatch(peer.peerId, WireType.PONG, { nonce: ping.payload.nonce });
    expect(peer.rtt).toBeGreaterThanOrEqual(0);
  });

  it('網に出る ID は暗号論的乱数で作る', () => {
    const ids = new Set(Array.from({ length: 200 }, () => CryptoUtils.generateId(10)));
    expect(ids.size).toBe(200);
    for (const id of ids) expect(id).toMatch(/^[0-9a-z]{10}$/);

  });
});
