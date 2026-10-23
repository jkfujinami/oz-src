import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { RingPosition } from '../../src/network/RingPosition';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { netGroupOf, groupCap } from '../../src/network/NetGroup';

beforeAll(async () => {
  await sodiumReady;
});

describe('RingPosition', () => {
  it('座標は peerId の純粋関数 (NodeIdentity.derivePosition と同じ値)', () => {
    const peerId = '9bf361b6706d6251f49efbe9f02823fa';
    expect(RingPosition.forPeer(peerId)).toBe(NodeIdentity.derivePosition(peerId));
    expect(RingPosition.forPeer(peerId)).toBe(RingPosition.forPeer(peerId));
    expect(RingPosition.of(peerId).value).toBe(RingPosition.forPeer(peerId));
  });

  it('既知の peerId の座標 (相互運用ベクタと同じ値)', () => {
    expect(RingPosition.forPeer('a57c8bec330e5bd8771c3248ddb69236')).toBe(0.562473337513834);
  });

  it('座標は [0, 1) に収まり、peerId が 1 文字違えば別の座標になる', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const id = sodium.to_hex(sodium.crypto_generichash(16, new Uint8Array([i, i >> 8]), null));
      const p = RingPosition.forPeer(id);
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThan(1);
      seen.add(p);
    }
    expect(seen.size).toBe(200);
  });

  it('座標はおおむね一様に散らばる (4 分割の各区間に 1 割以上)', () => {
    const buckets = [0, 0, 0, 0];
    for (let i = 0; i < 400; i++) {
      const id = sodium.to_hex(sodium.crypto_generichash(16, new Uint8Array([i & 0xff, i >> 8, 1]), null));
      buckets[Math.floor(RingPosition.forPeer(id) * 4)]++;
    }
    for (const b of buckets) expect(b).toBeGreaterThan(40);
  });

  describe('distance', () => {
    it('対称で、同じ点なら 0', () => {
      expect(RingPosition.distance(0.3, 0.3)).toBe(0);
      expect(RingPosition.distance(0.1, 0.4)).toBeCloseTo(0.3, 12);
      expect(RingPosition.distance(0.4, 0.1)).toBeCloseTo(0.3, 12);
    });

    it('リングを回り込んだ短い方の距離を返す', () => {
      expect(RingPosition.distance(0.05, 0.95)).toBeCloseTo(0.1, 12);
      expect(RingPosition.distance(0, 0.999)).toBeCloseTo(0.001, 12);
    });

    it('最大は 0.5 (正反対)', () => {
      expect(RingPosition.distance(0, 0.5)).toBe(0.5);
      expect(RingPosition.distance(0.25, 0.75)).toBe(0.5);
      for (let i = 0; i < 100; i++) {
        const a = i / 100, b = ((i * 37) % 100) / 100;
        const d = RingPosition.distance(a, b);
        expect(d).toBeGreaterThanOrEqual(0);
        expect(d).toBeLessThanOrEqual(0.5);
      }
    });
  });
});

describe('NetGroup (DegreeRebalance.test.ts を補う境界ケース)', () => {
  it('私設 IPv4 の範囲の境界', () => {
    expect(netGroupOf('172.15.0.1')).toBe('v4:172.15');
    expect(netGroupOf('172.16.0.1')).toBe('lan');
    expect(netGroupOf('172.31.255.1')).toBe('lan');
    expect(netGroupOf('172.32.0.1')).toBe('v4:172.32');
    expect(netGroupOf('100.63.0.1')).toBe('v4:100.63');
    expect(netGroupOf('100.64.0.1')).toBe('lan'); // CGNAT
    expect(netGroupOf('100.127.0.1')).toBe('lan');
    expect(netGroupOf('100.128.0.1')).toBe('v4:100.128');
    expect(netGroupOf('127.0.0.1')).toBe('lan');
    expect(netGroupOf('169.254.1.1')).toBe('lan');
    expect(netGroupOf('169.253.1.1')).toBe('v4:169.253');
    expect(netGroupOf('192.167.1.1')).toBe('v4:192.167');
  });

  it('TURN リレーは私設アドレスでも relay 区分 (リレーの出所でまとめる)', () => {
    expect(netGroupOf('10.0.0.1', 'relay')).toBe('relay:10.0');
    expect(netGroupOf('2001:db8:1:2::9', 'relay')).toBe('relay:2001:db8:1');
    // relay 以外の候補種別は通常どおり
    expect(netGroupOf('198.51.100.7', 'srflx')).toBe('v4:198.51');
    expect(netGroupOf('198.51.100.7', 'host')).toBe('v4:198.51');
  });

  it('IPv6: 角括弧・ゾーン ID・大文字・前後の空白を正規化する', () => {
    expect(netGroupOf('[2001:DB8:ABCD::1]')).toBe('v6:2001:db8:abcd');
    expect(netGroupOf('fe80::1%eth0')).toBe('lan');
    expect(netGroupOf('  2001:db8:abcd:1::5  ')).toBe('v6:2001:db8:abcd');
    expect(netGroupOf('2001:db8::1')).toBe('v6:2001:db8:0');
  });

  it('IPv6 の私設・ループバック', () => {
    expect(netGroupOf('fc00::1')).toBe('lan');
    expect(netGroupOf('fdff:1234::1')).toBe('lan'); // ULA fc00::/7
    expect(netGroupOf('fe80::abcd')).toBe('lan');
    expect(netGroupOf('febf::1')).toBe('lan'); // fe80::/10 の端
    expect(netGroupOf('fec0::1')).toBe('v6:fec0:0:0');
    expect(netGroupOf('::1')).toBe('lan');
    expect(netGroupOf('::')).toBe('v6:0:0:0');
  });

  it('不正な IPv6 は unknown', () => {
    for (const a of ['1::2::3', 'abcde::1', '1:2:3:4:5:6:7:8:9', '1:2:3', 'g::1', ':::']) {
      expect(netGroupOf(a), a).toBe('unknown');
    }
  });

  it('IPv4 射影 IPv6 (::ffff:a.b.c.d) は扱わない (unknown)', () => {
    expect(netGroupOf('::ffff:203.0.113.5')).toBe('unknown');
  });

  it('上位 2 オクテットが 255 を超える IPv4 は unknown', () => {
    expect(netGroupOf('256.1.1.1')).toBe('unknown');
    expect(netGroupOf('1.256.1.1')).toBe('unknown');
  });

  it('空・null・mDNS', () => {
    expect(netGroupOf('')).toBe('unknown');
    expect(netGroupOf(null)).toBe('unknown');
    expect(netGroupOf('ABCDEF.LOCAL')).toBe('lan');
  });

  it('同じ /16 の別アドレスは同じ区分、隣の /16 は別区分', () => {
    expect(netGroupOf('203.0.0.1')).toBe(netGroupOf('203.0.255.254'));
    expect(netGroupOf('203.0.0.1')).not.toBe(netGroupOf('203.1.0.1'));
  });

  it('groupCap: 区分数が 0 以下でも 1 区分として扱い、上限は 1 未満にならない', () => {
    expect(groupCap(16, 0)).toBe(16);
    expect(groupCap(16, -5)).toBe(16);
    expect(groupCap(16, 3)).toBe(6);
    expect(groupCap(16, 16)).toBe(1);
    expect(groupCap(16, 17)).toBe(1);
    expect(groupCap(0, 4)).toBe(1);
  });
});
