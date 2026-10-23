import { describe, it, expect } from 'vitest';
import sodium from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { boardTag, threadTag, dayOf, metaTagAge, replyTagAge, birthDayOfThread, mondayOf } from '../../src/crypto/PacketTag';
import { makeThreadId } from '../../src/logic/ThreadLimits';
import { posterId } from '../../src/logic/PosterId';
import { POW_POLICY, DAY_MS } from '../../src/crypto/PowPolicy';
import { buildPost } from '../helpers/postFixtures';

const engine = new CryptoEngine();
const NOW = Date.UTC(2026, 9, 14, 12, 0);
const K = new Uint8Array(32).fill(9);

describe('PacketTag: tag (12 ビット) と age', () => {
  it('板のメタ: tag = HMAC-SHA256(K_b, "oz/v5/board-tag" ‖ u32be(週の月曜)) の下位 12 ビット、age = 投稿日 − 月曜', () => {
    const day = dayOf(NOW);
    const msg = new Uint8Array([...new TextEncoder().encode('oz/v5/board-tag'), day >>> 24, (day >>> 16) & 255, (day >>> 8) & 255, day & 255]);
    const mac = sodium.crypto_auth_hmacsha256(msg, K);
    expect(boardTag(K, day)).toBe(((mac[0] << 8) | mac[1]) & 0xfff);
    const monday = mondayOf(day);
    expect(metaTagAge(K, NOW)).toEqual({ tag: boardTag(K, monday), age: day - monday });
    expect(boardTag(K, day + 1)).not.toBe(boardTag(K, day)); // 日ごとに違う (4096 分の 1 で偶然同じ値になりうるので、固定の鍵で確認)
  });

  it('板のメタは週単位: 同じ週の 7 日は同じ tag、age は 0..6、翌週の月曜で切り替わる', () => {
    // 2026-10-12 は月曜
    const monday = dayOf(Date.UTC(2026, 9, 12));
    expect(mondayOf(monday)).toBe(monday);
    for (let i = 0; i < 7; i++) {
      const t = (monday + i) * DAY_MS + 12 * 3600_000;
      expect(mondayOf(monday + i)).toBe(monday);
      expect(metaTagAge(K, t)).toEqual({ tag: boardTag(K, monday), age: i });
    }
    expect(mondayOf(monday + 7)).toBe(monday + 7);
    expect(metaTagAge(K, (monday + 7) * DAY_MS).age).toBe(0);
    // 1970-01-01 (木曜) の週の月曜は 1969-12-29
    expect(mondayOf(0)).toBe(-3);
  });

  it('返信: tag はスレ立て日で決まり (投稿日に依らない)、age = 投稿日 - スレ立て日', () => {
    const born = NOW - 5 * DAY_MS;
    const tid = makeThreadId(born, 'abcdefghij');
    expect(birthDayOfThread(tid)).toBe(dayOf(born));
    const a = replyTagAge(K, tid, NOW);
    const b = replyTagAge(K, tid, NOW + 2 * DAY_MS);
    expect(a.age).toBe(5);
    expect(b.age).toBe(7);
    expect(a.tag).toBe(b.tag);
    expect(a.tag).toBe(threadTag(K, dayOf(born)));
  });

  it('旧形式 (10 文字) の ID は日付を持たない: birthDay = 投稿日、age 0', () => {
    expect(birthDayOfThread('abcdefghij')).toBeNull();
    expect(replyTagAge(K, 'abcdefghij', NOW)).toEqual({ tag: threadTag(K, dayOf(NOW)), age: 0 });
  });

  it('スレ立てから 90 日を超えると書けない (RangeError)。90 日ちょうどは書ける', () => {
    expect(replyTagAge(K, makeThreadId(NOW - 90 * DAY_MS, 'abcdefghij'), NOW).age).toBe(90);
    expect(() => replyTagAge(K, makeThreadId(NOW - 91 * DAY_MS, 'abcdefghij'), NOW)).toThrow(RangeError);
  });
});

describe('読み手: tag / age が合わないパケットは復号の前に落とす', () => {
  const BOARD = 'vip';

  it('★別のスレ・別の板・別の日の tag を持つパケットは、鍵が合っていても読まない', async () => {
    const key = sodium.randombytes_buf(32);
    const tid = makeThreadId(NOW - 3 * DAY_MS, 'abcdefghij');
    const { packet } = await buildPost({ content: 'x', threadKey: key, threadId: tid, now: NOW, pow: 'fake' });
    const ctx = { kind: 'reply', boardId: BOARD, threadId: tid } as const;
    expect(packet.age).toBe(3);
    expect(await PacketBuilder.verifyAndDecrypt(packet, key, ctx, engine)).not.toBeNull();

    // tag / age を 1 つ書き換える (AAD にも入るので SIV でも落ちるが、ここは足切りで落ちる)
    expect(PacketBuilder.tagAgeMatches({ ...packet, tag: packet.tag ^ 1 }, key, ctx)).toBe(false);
    expect(PacketBuilder.tagAgeMatches({ ...packet, age: 4 }, key, ctx)).toBe(false);
    expect(await PacketBuilder.verifyAndDecrypt({ ...packet, tag: packet.tag ^ 1 }, key, ctx, engine)).toBeNull();
    expect(await PacketBuilder.verifyAndDecrypt({ ...packet, age: 4 }, key, ctx, engine)).toBeNull();
    // 別のスレとして読む (スレ立て日が違えば tag が違う)
    const other = makeThreadId(NOW - 4 * DAY_MS, 'abcdefghij');
    expect(PacketBuilder.tagAgeMatches(packet, key, { ...ctx, threadId: other })).toBe(false);
    // 板のメタとして読むと age 0 でないので不一致
    expect(PacketBuilder.tagAgeMatches(packet, key, { kind: 'meta', boardId: BOARD })).toBe(false);
  });

  it('板のメタは、その週の板の tag と「投稿日 − 月曜」の age でなければ読まない', async () => {
    const key = sodium.randombytes_buf(32);
    const { packet } = await buildPost({ content: 'タイトル', threadKey: key, postType: 1, threadId: 'abcdefghij', now: NOW, pow: 'fake' });
    const ctx = { kind: 'meta', boardId: BOARD } as const;
    const expected = metaTagAge(key, NOW);
    expect(packet.tag).toBe(expected.tag);
    expect(packet.age).toBe(expected.age);
    expect((await PacketBuilder.verifyAndDecrypt(packet, key, ctx, engine))!.thread_id).toBe('abcdefghij');
    expect(await PacketBuilder.verifyAndDecrypt({ ...packet, age: (packet.age + 1) % 7 }, key, ctx, engine)).toBeNull();
    // 別の週の時刻に付け替えた複製は tag と age の組が合わない (4096 分の 1 で tag が偶然一致しても age で落ちうる)
    const moved = { ...packet, timestamp: packet.timestamp + 7 * DAY_MS };
    const movedExpected = metaTagAge(key, moved.timestamp);
    expect(PacketBuilder.tagAgeMatches(moved, key, ctx)).toBe(movedExpected.tag === packet.tag && movedExpected.age === packet.age);
  });

  it('スレ立てから 90 日を超えるスレには、作者が返信を作れない', async () => {
    const tid = makeThreadId(NOW - 91 * DAY_MS, 'abcdefghij');
    await expect(buildPost({ content: 'x', threadId: tid, now: NOW, pow: 'fake' })).rejects.toThrow(RangeError);
    expect(POW_POLICY.MAX_AGE_DAYS).toBe(90);
  });
});

describe('PosterId: ID の表示', () => {
  const trip = new Uint8Array(32).fill(1);
  const session = new Uint8Array(32).fill(2);

  it('トリップ有りはトリップ鍵とスレッドから導く (スレごとに変わる)。セッション鍵は使わない', () => {
    const a = posterId({ trip_pubkey: trip, session_pubkey: null }, 'thread-a');
    const b = posterId({ trip_pubkey: trip, session_pubkey: null }, 'thread-b');
    expect(a).not.toBe(b);
    expect(posterId({ trip_pubkey: trip, session_pubkey: session }, 'thread-a')).toBe(a);
    expect(a).toHaveLength(6);
  });

  it('トリップ無しはセッション鍵から。鍵が無ければ ???', () => {
    expect(posterId({ session_pubkey: session }, 't')).toBe(posterId({ session_pubkey: session }, 'u'));
    expect(posterId({}, 't')).toBe('???');
  });
});
