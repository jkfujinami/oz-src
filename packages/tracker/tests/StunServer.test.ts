import { describe, it, expect, afterEach } from 'vitest';
import dgram from 'node:dgram';
import {
  StunServer, StunRateLimiter, STUN_LIMITS, STUN_MAGIC_COOKIE, parseBindingRequest, buildBindingResponse,
} from '../src/StunServer';

const hex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// RFC 5769 の transaction id (b7e7a701 bc34d686 fa87dfae)
const TX = hex('b7e7a701bc34d686fa87dfae');

function request(tx: Uint8Array, attrs: Uint8Array = new Uint8Array(0)): Uint8Array {
  const out = new Uint8Array(20 + attrs.length);
  const v = new DataView(out.buffer);
  v.setUint16(0, 0x0001);
  v.setUint16(2, attrs.length);
  v.setUint32(4, STUN_MAGIC_COOKIE);
  out.set(tx, 8);
  out.set(attrs, 20);
  return out;
}

describe('STUN コーデック', () => {
  it('RFC 5769 の IPv4 ベクタ (192.0.2.1:32853) と一致する', () => {
    // RFC 5769 §2.2 の XOR-MAPPED-ADDRESS (SOFTWARE などは載せない最小形)
    const res = buildBindingResponse(TX, '192.0.2.1', 32853)!;
    expect(toHex(res)).toBe('0101000c2112a442' + 'b7e7a701bc34d686fa87dfae' + '00200008' + '0001a147e112a643');
  });

  it('RFC 5769 の IPv6 ベクタ (2001:db8:1234:5678:11:2233:4455:6677 port 32853) と一致する', () => {
    const res = buildBindingResponse(TX, '2001:db8:1234:5678:11:2233:4455:6677', 32853)!;
    expect(toHex(res)).toBe(
      '01010018' + '2112a442' + 'b7e7a701bc34d686fa87dfae' + '00200014' + '0002a147' + '0113a9faa5d3f179bc25f4b5bed2b9d9',
    );
  });

  it('IPv4 射影アドレスは IPv4 として扱い、:: 省略形も解釈する', () => {
    expect(toHex(buildBindingResponse(TX, '::ffff:192.0.2.1', 32853)!)).toBe(toHex(buildBindingResponse(TX, '192.0.2.1', 32853)!));
    const lo = buildBindingResponse(TX, '::1', 1)!;
    expect(lo.length).toBe(44);
    expect(buildBindingResponse(TX, 'not-an-ip', 1)).toBeNull();
    expect(buildBindingResponse(TX, '1.2.3.4', 70000)).toBeNull();
  });

  it('応答は要求 (20 バイト) の高々 2.2 倍', () => {
    expect(buildBindingResponse(TX, '1.2.3.4', 1)!.length).toBe(32);
    expect(buildBindingResponse(TX, '::1', 1)!.length).toBe(44);
  });

  it('正しい Binding Request から transaction id を取り出す。属性付きも可', () => {
    expect(parseBindingRequest(request(TX))).toEqual(TX);
    const attr = hex('80220004 74657374'); // SOFTWARE "test"
    expect(parseBindingRequest(request(TX, attr))).toEqual(TX);
  });

  it('壊れたもの・別のメッセージは null (例外を投げない)', () => {
    const good = request(TX);
    const mut = (f: (b: Uint8Array) => void) => { const b = good.slice(); f(b); return b; };
    expect(parseBindingRequest(new Uint8Array(0))).toBeNull();
    expect(parseBindingRequest(good.slice(0, 19))).toBeNull();
    expect(parseBindingRequest(mut((b) => { b[7] ^= 1; }))).toBeNull(); // magic cookie
    expect(parseBindingRequest(mut((b) => { b[1] = 0x02; }))).toBeNull(); // 別のメソッド
    expect(parseBindingRequest(mut((b) => { b[0] = 0x81; }))).toBeNull(); // 先頭 2 ビット
    expect(parseBindingRequest(mut((b) => { b[3] = 4; }))).toBeNull(); // 長さが実際と違う
    expect(parseBindingRequest(mut((b) => { b[0] = 0x01; b[1] = 0x01; }))).toBeNull(); // 応答
    expect(parseBindingRequest(request(TX, hex('80220008 74657374')))).toBeNull(); // 属性が本体を超える
    expect(parseBindingRequest(request(TX, hex('80220001 74')))).toBeNull(); // 4 の倍数でない
    expect(parseBindingRequest(request(TX, new Uint8Array(600)))).toBeNull(); // 大きすぎる
    const rnd = new Uint8Array(64);
    for (let i = 0; i < 200; i++) {
      for (let j = 0; j < rnd.length; j++) rnd[j] = Math.floor(Math.random() * 256);
      expect(() => parseBindingRequest(rnd)).not.toThrow();
    }
  });
});

describe('応答数の制限', () => {
  it('同じ IP は 1 秒あたり perIpPerSec まで。別の IP には影響しない。時間で回復する', () => {
    let t = 1_000_000;
    const lim = new StunRateLimiter(() => t);
    let ok = 0;
    for (let i = 0; i < 100; i++) if (lim.allow('1.1.1.1')) ok++;
    expect(ok).toBe(STUN_LIMITS.perIpPerSec);
    expect(lim.allow('2.2.2.2')).toBe(true);
    t += 1000;
    expect(lim.allow('1.1.1.1')).toBe(true);
  });

  it('全体の上限を超えると、別の送信元でも捨てる', () => {
    const lim = new StunRateLimiter(() => 5_000);
    let ok = 0;
    for (let i = 0; i < STUN_LIMITS.globalPerSec + 1000; i++) if (lim.allow(`ip${i}`)) ok++;
    expect(ok).toBe(STUN_LIMITS.globalPerSec);
  });
});

describe('UDP 結合 (loopback)', () => {
  let server: StunServer | null = null;
  const sockets: dgram.Socket[] = [];
  afterEach(async () => {
    for (const s of sockets.splice(0)) s.close();
    await server?.close();
    server = null;
  });

  function client(): Promise<{ sock: dgram.Socket; port: number }> {
    return new Promise((resolve) => {
      const sock = dgram.createSocket('udp4');
      sockets.push(sock);
      sock.bind(0, '127.0.0.1', () => resolve({ sock, port: sock.address().port }));
    });
  }
  const recv = (sock: dgram.Socket, ms: number): Promise<Buffer | null> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => { sock.off('message', on); resolve(null); }, ms);
      const on = (m: Buffer) => { clearTimeout(timer); resolve(m); };
      sock.once('message', on);
    });

  it('Binding Request に、送信元のアドレスとポートを XOR-MAPPED-ADDRESS で返す', async () => {
    server = new StunServer();
    const port = await server.listen(0, '127.0.0.1');
    const { sock, port: myPort } = await client();
    sock.send(request(TX), port, '127.0.0.1');
    const res = await recv(sock, 2000);
    expect(res).not.toBeNull();
    const r = new Uint8Array(res!);
    const v = new DataView(r.buffer, r.byteOffset, r.byteLength);
    expect(v.getUint16(0)).toBe(0x0101);
    expect(toHex(r.slice(8, 20))).toBe(toHex(TX));
    expect(v.getUint16(20)).toBe(0x0020);
    expect(r[25]).toBe(0x01);
    expect(v.getUint16(26) ^ (STUN_MAGIC_COOKIE >>> 16)).toBe(myPort);
    const ip = [0, 1, 2, 3].map((i) => r[28 + i]! ^ ((STUN_MAGIC_COOKIE >>> (24 - 8 * i)) & 0xff)).join('.');
    expect(ip).toBe('127.0.0.1');
  });

  it('壊れたパケットには何も返さず、その後も動き続ける。件数だけ数える', async () => {
    server = new StunServer();
    const port = await server.listen(0, '127.0.0.1');
    const { sock } = await client();
    sock.send(Buffer.from('GET / HTTP/1.1\r\n\r\n'), port, '127.0.0.1');
    sock.send(Buffer.alloc(0), port, '127.0.0.1');
    expect(await recv(sock, 300)).toBeNull();
    sock.send(request(TX), port, '127.0.0.1');
    expect(await recv(sock, 2000)).not.toBeNull();
    expect(server.takeCounts()).toEqual({ responded: 1, ignored: 2, limited: 0 });
  });

  it('連打しても応答は送信元 IP あたりの上限まで', async () => {
    server = new StunServer();
    const port = await server.listen(0, '127.0.0.1');
    const { sock } = await client();
    let got = 0;
    sock.on('message', () => { got++; });
    for (let i = 0; i < 50; i++) sock.send(request(TX), port, '127.0.0.1');
    await new Promise((r) => setTimeout(r, 500));
    expect(got).toBeLessThanOrEqual(STUN_LIMITS.perIpPerSec + 1);
    expect(got).toBeGreaterThan(0);
    expect(server.takeCounts().limited).toBeGreaterThan(0);
  });
});
