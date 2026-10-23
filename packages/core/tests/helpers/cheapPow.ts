import { PACKET_VERSION, derivePacketId, minutesToMs, msToMinutes } from '../../src/crypto/PowPolicy';
import { CHEAP_SOLUTION } from './cheapPowMock';
import type { GossipPacket } from '../../src/types';

export { cheapPowPolicyFactory } from './cheapPowMock';

/** 安い PoW の印を付けたパケット (cheapPowPolicyFactory でモックしたファイルだけで有効)。payload が違えば id も違う */
export function makeCheapPacket(payloadBytes: number[] | Uint8Array = [1, 2, 3, 4], now: number = Date.now()): GossipPacket {
  const given = payloadBytes instanceof Uint8Array ? payloadBytes : Uint8Array.from(payloadBytes);
  const payload = new Uint8Array(Math.max(given.length, 16 + 1 + 96)); // 検証を通る最小のペイロード長
  payload.set(given, 0);
  const time = msToMinutes(now);
  return {
    packet_id: derivePacketId({ version: PACKET_VERSION, time, tag: 1, age: 0, payload }),
    timestamp: minutesToMs(time),
    tag: 1, age: 0, effort_exp: 0, pow_nonce: 0, pow_solution: CHEAP_SOLUTION, payload,
  };
}
