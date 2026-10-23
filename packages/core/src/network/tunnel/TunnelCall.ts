import type { PeerId } from '../../types';
import { newRespKey, sealRequest, decryptChunk } from './TunnelCrypto';
import type { TunnelClient } from './TunnelClient';

/** 要求の宛先: 保持者の SID と、その受け口 (leaseSet の gateway と tunnelId) */
export interface TunnelTarget {
  sidBytes: Uint8Array;
  gateway: PeerId;
  tunnelId: Uint8Array;
}

export interface TunnelCallOptions {
  /** 応答の片が 1 つも届かないまま待つ上限 (ms)。片が届くたびに延びる */
  inactivityMs: number;
  /** 受け付ける応答の大きさ (復号後の合計) と片の数の上限。超えたら失敗 */
  maxBytes: number;
  maxPieces: number;
  /** 中止。以後の片は捨てる */
  signal?: AbortSignal;
}

export interface TunnelCallResult {
  /** 完全な応答 (復号済み・片を結合したもの)。失敗・中止なら null */
  data: Uint8Array | null;
  /** 失敗の理由 (経路の ERROR か手元の失敗)。時間切れ・改ざん・中止は undefined */
  error?: { code: number; local?: 'no-first-hop' | 'first-hop-lost' | 'too-many' };
}

/** 復号できない片がこれだけ来たら諦める (経路の途中で改ざんされている) */
const MAX_BAD_PIECES = 3;

/**
 * 要求を 1 つ出して、応答 1 つ分 (全部の片が揃い、最後の片が復号した中身の final) を返す。失敗・中止は data = null。
 * 経路の ERROR (BUSY など) は error に載せる: 呼び出し側は「制限に当たった」(待てばよい) と「届かない」(別の保持者へ) を分けられる。
 *
 * ★ HistoryClient.requestOnce と同じ規則 (大容量ファイルの預け入れ・取得で使い回す):
 *   - フレームの final (平文) ではなく、**復号した中身の final** を使う。途中の片を黙って落とされても完結と見なさない。
 *   - 片の番号の重複・final より後ろの片・合計の大きさの超過は失敗。
 *   - respKey は要求ごとの乱数で、使い終えたら消す。
 */
export function callTunnel(
  client: Pick<TunnelClient, 'request'>,
  target: TunnelTarget,
  kind: number,
  payload: Uint8Array,
  opts: TunnelCallOptions,
): Promise<TunnelCallResult> {
  return new Promise((resolve) => {
    if (opts.signal?.aborted) return resolve({ data: null });
    const respKey = newRespKey();
    const sealed = sealRequest(target.sidBytes, kind, respKey, payload);
    if (!sealed) return resolve({ data: null });

    const parts = new Map<number, Uint8Array>();
    let finalSeq = -1;
    let bytes = 0;
    let bad = 0;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let handle: { cancel(): void } | null = null;

    const end = (res: Uint8Array | null, error?: TunnelCallResult['error']) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      handle?.cancel();
      respKey.fill(0);
      resolve(error ? { data: res, error } : { data: res });
    };
    const onAbort = () => end(null);
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    const arm = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => end(null), opts.inactivityMs);
    };

    handle = client.request({ gateway: target.gateway, tunnelId: target.tunnelId, body: sealed }, (ev) => {
      if (settled) return;
      if (ev.type === 'error') return end(null, { code: ev.code, local: ev.local });
      const dec = decryptChunk(respKey, kind, ev.seq, ev.body);
      if (!dec) {
        if (++bad >= MAX_BAD_PIECES) end(null);
        return;
      }
      if (parts.has(ev.seq)) return;
      if (parts.size >= opts.maxPieces) return end(null);
      if (finalSeq >= 0 && ev.seq > finalSeq) return end(null);
      if (dec.final) {
        if (finalSeq >= 0 && finalSeq !== ev.seq) return end(null);
        finalSeq = ev.seq;
        if ([...parts.keys()].some(s => s > finalSeq)) return end(null);
      }
      parts.set(ev.seq, dec.data);
      bytes += dec.data.length;
      if (bytes > opts.maxBytes) return end(null);
      arm();
      if (finalSeq >= 0 && parts.size === finalSeq + 1) {
        const out = new Uint8Array(bytes);
        let o = 0;
        for (let i = 0; i <= finalSeq; i++) {
          const p = parts.get(i);
          if (!p) return end(null);
          out.set(p, o);
          o += p.length;
        }
        end(out);
      }
    });
    if (handle) arm();
    else end(null);
  });
}
