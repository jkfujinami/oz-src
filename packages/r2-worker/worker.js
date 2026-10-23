/**
 * Cloudflare Workers デプロイ用単一ファイル Gatekeeper & IAS3 Slab Relay Worker (`worker.js`)。
 *
 * クレジットカード登録不要で `npx wrangler deploy` だけで即座に稼働する。
 * 1. Internet Archive (IAS3) 互換 Slab エンドポイント:
 *    - `PUT /ias3/{itemIdentifier}/{slabFilename}`:
 *      `Authorization: LOW <access>:<secret>`, `x-archive-queue-derive: 0`, `x-archive-meta-noindex: true` を検証し、
 *      シャッフル済み Slab バイナリを保存 (または `X-Ozzy-Forward-IA: 1` 指定時は実 `s3.us.archive.org` へ中継)。
 *    - `GET /download/{itemIdentifier}/{slabFilename}`:
 *      `Range: bytes=start-end` に対して `206 Partial Content` で指定 4 MiB (または 64 KiB) スライスのみを返却。
 *    - `DELETE /ias3/{itemIdentifier}/{slabFilename}`:
 *      Polite DELETE により Slab を物理削除し `204 No Content` を返却 (削除後の GET は `404 Not Found`)。
 * 2. `/ozzy/v2/status`, `/ozzy/v2/chunk`, `/ozzy/v2/touch`:
 *    R2 バインディング (`env.OZZY_BUCKET`) が無い環境でも Edge Cache + RAM フォールバックバケットで自律動作。
 */

const TOTAL_SLOTS = 2304; // 9.0 GiB = 2,304 × 4 MiB
const MANIFEST_POOL_SLOTS = 230; // 先頭 10% (0..229): Manifest 専用保護プール
const CHUNK_BYTES = 4 * 1024 * 1024; // 4,194,304 B
const TAG_BYTES = 16;
const SLOT_META_BYTES = 20;
const MONTHLY_CLASS_A_CAP = 500_000;
const MONTHLY_CLASS_B_CAP = 5_000_000;
const HOT_PROTECT_DAYS = 30;
const TOUCH_EXTEND_DAYS = 75;
const POLITE_SLAB_CAP_BYTES = 512 * 1024 * 1024; // Isolate 内キャッシュ上限

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers':
    'Authorization, Content-Type, Range, User-Agent, X-Delete-Token, X-Ozzy-Pool, X-Ozzy-Candidates, X-Ozzy-TTL-Days, X-Ozzy-Quota-Proof, X-Ozzy-Tag, X-Ozzy-Forward-IA, X-Ozzy-Target-Url, X-Ozzy-Target-Method, X-Ozzy-Target-Headers, x-archive-auto-make-bucket, x-archive-meta-mediatype, x-archive-meta-noindex, x-archive-queue-derive',
  'Access-Control-Expose-Headers':
    'Accept-Ranges, Content-Range, Content-Length, X-Token, X-Ozzy-Proxied-Status, X-Ozzy-Slot-Id, X-Ozzy-Tag, X-Ozzy-Slab-Noindex, X-Ozzy-Slab-Derive',
  'Access-Control-Max-Age': '86400',
};

const ALLOWED_LOCKER_HOSTS = new Set([
  'archive.org',
  's3.us.archive.org',
  'catbox.moe',
  'files.catbox.moe',
  'litterbox.catbox.moe',
  'litter.catbox.moe',
  '0x0.st',
  'x0.at',
  'uguu.se',
  'pomf2.lain.la',
  'qu.ax',
  'api.gofile.io',
  'upload.gofile.io',
  'pixeldrain.com',
]);

function isAllowedOverseasLockerHost(hostname) {
  const h = hostname.toLowerCase();
  if (ALLOWED_LOCKER_HOSTS.has(h)) return true;
  if (
    h.endsWith('.archive.org') ||
    h.endsWith('.gofile.io') ||
    h.endsWith('.catbox.moe') ||
    h.endsWith('.uguu.se')
  ) {
    return true;
  }
  return false;
}

let memorySlots = null;
let classACount = 0;
let classBCount = 0;
let lastMetaFlushMs = 0;

// クレカ不要モード用のインメモリ + Edge Cache ストレージマップ
const fallbackObjects = new Map();
const iaSlabs = new Map();
let iaSlabTotalBytes = 0;
let iaPutCount = 0;
let iaRangeGetCount = 0;
let iaDeleteCount = 0;

function getBucket(env) {
  if (env && env.OZZY_BUCKET) return env.OZZY_BUCKET;
  return {
    async get(key, opts) {
      const data = fallbackObjects.get(key);
      if (!data) return null;
      if (opts && opts.range) {
        const start = opts.range.offset ?? 0;
        const len = opts.range.length ?? data.byteLength - start;
        const sliced = data.subarray(start, start + len);
        return {
          size: sliced.byteLength,
          body: sliced,
          async arrayBuffer() {
            return sliced.buffer.slice(sliced.byteOffset, sliced.byteOffset + sliced.byteLength);
          },
        };
      }
      return {
        size: data.byteLength,
        body: data,
        async arrayBuffer() {
          return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        },
      };
    },
    async put(key, val) {
      const bytes = val instanceof Uint8Array ? new Uint8Array(val) : new Uint8Array(await new Response(val).arrayBuffer());
      fallbackObjects.set(key, bytes);
    },
    async delete(key) {
      fallbackObjects.delete(key);
    },
  };
}

function currentEpochDay() {
  return Math.floor(Date.now() / 86_400_000);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function ensureMetaLoaded(bucket) {
  if (memorySlots) return memorySlots;
  classBCount++;
  const obj = await bucket.get('ozzy/m');
  const slots = [];
  if (obj && obj.size === TOTAL_SLOTS * SLOT_META_BYTES) {
    const buf = new Uint8Array(await obj.arrayBuffer());
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < TOTAL_SLOTS; i++) {
      const off = i * SLOT_META_BYTES;
      slots.push({
        tag: buf.slice(off, off + 16),
        expireDay: dv.getUint16(off + 16, true),
        lastFetchedDay: dv.getUint16(off + 18, true),
      });
    }
  } else {
    for (let i = 0; i < TOTAL_SLOTS; i++) {
      slots.push({ tag: new Uint8Array(16), expireDay: 0, lastFetchedDay: 0 });
    }
  }
  memorySlots = slots;
  lastMetaFlushMs = Date.now();
  return slots;
}

async function maybeFlushMeta(bucket, force = false) {
  if (!memorySlots) return;
  const now = Date.now();
  if (!force && now - lastMetaFlushMs < 3_600_000) return;
  if (classACount >= MONTHLY_CLASS_A_CAP) return;
  const buf = new Uint8Array(TOTAL_SLOTS * SLOT_META_BYTES);
  const dv = new DataView(buf.buffer);
  for (let i = 0; i < TOTAL_SLOTS; i++) {
    const off = i * SLOT_META_BYTES;
    buf.set(memorySlots[i].tag, off);
    dv.setUint16(off + 16, memorySlots[i].expireDay & 0xffff, true);
    dv.setUint16(off + 18, memorySlots[i].lastFetchedDay & 0xffff, true);
  }
  classACount++;
  await bucket.put('ozzy/m', buf);
  lastMetaFlushMs = now;
}

function selectVictimSlot(candidates, slots, today) {
  let bestSlot = -1;
  let minVal = Infinity;
  for (const c of candidates) {
    if (slots[c].expireDay === 0 || slots[c].expireDay <= today) {
      if (slots[c].expireDay < minVal) {
        minVal = slots[c].expireDay;
        bestSlot = c;
      }
    }
  }
  if (bestSlot !== -1) return { slotId: bestSlot, reason: 'expired' };

  minVal = Infinity;
  for (const c of candidates) {
    if (slots[c].lastFetchedDay === 0 && slots[c].expireDay < minVal) {
      minVal = slots[c].expireDay;
      bestSlot = c;
    }
  }
  if (bestSlot !== -1) return { slotId: bestSlot, reason: 'unfetched' };

  minVal = Infinity;
  for (const c of candidates) {
    if (today - slots[c].lastFetchedDay >= HOT_PROTECT_DAYS && slots[c].lastFetchedDay < minVal) {
      minVal = slots[c].lastFetchedDay;
      bestSlot = c;
    }
  }
  if (bestSlot !== -1) return { slotId: bestSlot, reason: 'lru_cold' };

  return null;
}

const ZERO_TAG_16 = new Uint8Array(16);

function isAllZeroTag(tag) {
  return bytesEqual(tag, ZERO_TAG_16);
}

function evictOldestSlabsIfNeeded(requiredBytes) {
  while (iaSlabTotalBytes + requiredBytes > POLITE_SLAB_CAP_BYTES && iaSlabs.size > 0) {
    let oldestKey = null;
    let oldestTime = Infinity;
    for (const [k, v] of iaSlabs.entries()) {
      if (v.lastAccessedMs < oldestTime) {
        oldestTime = v.lastAccessedMs;
        oldestKey = k;
      }
    }
    if (!oldestKey) break;
    const victim = iaSlabs.get(oldestKey);
    iaSlabTotalBytes -= victim.data.byteLength;
    iaSlabs.delete(oldestKey);
    iaDeleteCount++;
  }
}


/** IAS3 互換の PUT / DELETE の資格情報の指紋 (同じ Authorization を持つ人だけが上書き・削除できる) */
async function authDigestOf(request) {
  const auth = request.headers.get('Authorization') ?? '';
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(auth))));
}

/** IAS3 互換の Slab の大きさの上限 (Worker のメモリと KV の値の上限 25 MiB に合わせる) */
const IA_SLAB_MAX_BYTES = 64 * 1024 * 1024;
const KV_VALUE_MAX_BYTES = 24 * 1024 * 1024;

export class OzzySlabVaultDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.slabs = new Map();
    this.deletedTombstones = new Set();
    this.totalBytes = 0;

    // Oz Tracker Protocol v3 エッジセッション管理
    this.trackerSessions = new Map(); // peerIdHex -> { ws, peerIdBytes }
    this.trackerConnections = new Map(); // ws -> ConnState
  }

  handleTrackerClose(ws) {
    const conn = this.trackerConnections.get(ws);
    if (!conn) return;
    this.trackerConnections.delete(ws);
    if (conn.timer) clearTimeout(conn.timer);
    if (conn.peerIdHex) {
      const cur = this.trackerSessions.get(conn.peerIdHex);
      if (cur && cur.ws === ws) {
        this.trackerSessions.delete(conn.peerIdHex);
      }
    }
  }

  /** その Slab を置いた資格情報の指紋 (無ければ null) */
  async slabOwner(slabKey) {
    const mem = this.slabs.get(slabKey);
    if (mem && mem.authDigest) return mem.authDigest;
    if (this.env && this.env.OZZY_SLAB_KV) {
      const r = await this.env.OZZY_SLAB_KV.getWithMetadata(`slab:${slabKey}`, 'arrayBuffer');
      if (r && r.value) return (r.metadata && r.metadata.auth) || null;
    }
    return null;
  }

  evictIfNeeded(requiredBytes) {
    while (this.totalBytes + requiredBytes > POLITE_SLAB_CAP_BYTES && this.slabs.size > 0) {
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, v] of this.slabs.entries()) {
        if (v.lastAccessedMs < oldestTime) {
          oldestTime = v.lastAccessedMs;
          oldestKey = k;
        }
      }
      if (!oldestKey) break;
      const victim = this.slabs.get(oldestKey);
      this.totalBytes -= victim.data.byteLength;
      this.slabs.delete(oldestKey);
    }
  }

  async fetch(request) {
    const url = new URL(request.url);

    // =========================================================================
    // 0. Oz WebSocket P2P トラッカー (/ws)
    // =========================================================================
    if (url.pathname === '/ws') {
      const upgrade = request.headers.get('Upgrade') ?? '';
      if (upgrade.toLowerCase() !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
      }

      const pair = new WebSocketPair();
      const clientWs = pair[0];
      const serverWs = pair[1];
      serverWs.accept();

      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const hostHeader = (request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? url.host)
        .trim()
        .toLowerCase()
        .replace(/:(80|443)$/, '');

      const connState = {
        ws: serverWs,
        nonce,
        host: hostHeader,
        peerIdHex: null,
        peerIdBytes: null,
        timer: null,
      };
      this.trackerConnections.set(serverWs, connState);

      connState.timer = setTimeout(() => {
        connState.timer = null;
        if (!connState.peerIdHex) {
          try {
            serverWs.send(Uint8Array.of(0x03, 11)); // timeout
            serverWs.close();
          } catch {}
          this.handleTrackerClose(serverWs);
        }
      }, 10000);

      // HELLO (0x01 || v=3 || nonce 32B) をクライアントへ送信
      const hello = new Uint8Array(34);
      hello[0] = 0x01;
      hello[1] = 0x03;
      hello.set(nonce, 2);
      serverWs.send(hello);

      serverWs.addEventListener('message', async (event) => {
        let b;
        if (event.data instanceof ArrayBuffer) b = new Uint8Array(event.data);
        else if (event.data instanceof Uint8Array) b = event.data;
        else {
          try { serverWs.send(Uint8Array.of(0x03, 1)); serverWs.close(); } catch {}
          this.handleTrackerClose(serverWs);
          return;
        }

        if (b.length < 1) return;
        const type = b[0];

        // JOIN (0x11)
        if (type === 0x11) {
          if (connState.peerIdHex || connState.nonce.length !== 32 || b.length < 103) {
            try { serverWs.send(Uint8Array.of(0x03, 1)); serverWs.close(); } catch {}
            this.handleTrackerClose(serverWs);
            return;
          }
          const v = b[1];
          if (v !== 3) {
            try { serverWs.send(Uint8Array.of(0x03, 2)); serverWs.close(); } catch {}
            this.handleTrackerClose(serverWs);
            return;
          }
          const pubkey = b.subarray(2, 34);
          const sig = b.subarray(38, 102);
          const hostLen = b[102];
          if (103 + hostLen !== b.length) {
            try { serverWs.send(Uint8Array.of(0x03, 1)); serverWs.close(); } catch {}
            this.handleTrackerClose(serverWs);
            return;
          }

          let claimedHost = '';
          try {
            claimedHost = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(103, 103 + hostLen)).toLowerCase();
          } catch {
            try { serverWs.send(Uint8Array.of(0x03, 1)); serverWs.close(); } catch {}
            this.handleTrackerClose(serverWs);
            return;
          }

          // peerId 導出: SHA256("OZ/v3/peerid" || pubkey)[0..16]
          const pDomain = new TextEncoder().encode('OZ/v3/peerid');
          const pBuf = new Uint8Array(pDomain.length + pubkey.length);
          pBuf.set(pDomain, 0);
          pBuf.set(pubkey, pDomain.length);
          const pHash = await crypto.subtle.digest('SHA-256', pBuf);
          const peerIdBytes = new Uint8Array(pHash, 0, 16);
          let peerIdHex = '';
          for (let i = 0; i < 16; i++) peerIdHex += peerIdBytes[i].toString(16).padStart(2, '0');

          // 署名検証: Ed25519(domain || nonce || lp16(peerIdHex) || lp16(trackerHost))
          const domain = new TextEncoder().encode('OZ/v1/tracker-join');
          const peerBytes = new TextEncoder().encode(peerIdHex);
          const hostBytes = new TextEncoder().encode(claimedHost);
          const msgBuf = new Uint8Array(domain.length + 32 + 2 + peerBytes.length + 2 + hostBytes.length);
          let off = 0;
          msgBuf.set(domain, off); off += domain.length;
          msgBuf.set(connState.nonce, off); off += 32;
          new DataView(msgBuf.buffer).setUint16(off, peerBytes.length, false); off += 2;
          msgBuf.set(peerBytes, off); off += peerBytes.length;
          new DataView(msgBuf.buffer).setUint16(off, hostBytes.length, false); off += 2;
          msgBuf.set(hostBytes, off);

          connState.nonce = new Uint8Array(0); // 使い捨て
          try {
            const key = await crypto.subtle.importKey(
              'raw',
              pubkey.buffer.slice(pubkey.byteOffset, pubkey.byteOffset + pubkey.byteLength),
              { name: 'Ed25519' },
              false,
              ['verify']
            );
            const ok = await crypto.subtle.verify(
              'Ed25519',
              key,
              sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength),
              msgBuf.buffer.slice(msgBuf.byteOffset, msgBuf.byteOffset + msgBuf.byteLength)
            );
            if (!ok) {
              try { serverWs.send(Uint8Array.of(0x03, 4)); serverWs.close(); } catch {}
              this.handleTrackerClose(serverWs);
              return;
            }
          } catch {
            try { serverWs.send(Uint8Array.of(0x03, 4)); serverWs.close(); } catch {}
            this.handleTrackerClose(serverWs);
            return;
          }

          const existing = this.trackerSessions.get(peerIdHex);
          if (existing && existing.ws !== serverWs) {
            try { existing.ws.close(); } catch {}
          }

          this.trackerSessions.set(peerIdHex, { ws: serverWs, peerIdBytes });
          connState.peerIdHex = peerIdHex;
          connState.peerIdBytes = peerIdBytes;
          if (connState.timer) {
            clearTimeout(connState.timer);
            connState.timer = null;
          }

          // PEERS (0x02) 返却 (ランダム最大 8 ピア)
          const candidates = [];
          for (const [id, entry] of this.trackerSessions) {
            if (id !== peerIdHex) candidates.push(entry.peerIdBytes);
          }
          for (let i = candidates.length - 1; i > 0; i--) {
            const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
            const temp = candidates[i];
            candidates[i] = candidates[j];
            candidates[j] = temp;
          }
          const selected = candidates.slice(0, 8);
          const peersFrame = new Uint8Array(2 + selected.length * 16);
          peersFrame[0] = 0x02;
          peersFrame[1] = selected.length;
          for (let i = 0; i < selected.length; i++) {
            peersFrame.set(selected[i], 2 + i * 16);
          }
          serverWs.send(peersFrame);
          return;
        }

        // RELAY_SDP (0x04) / RELAY_ICE (0x05)
        if (type === 0x04 || type === 0x05) {
          if (!connState.peerIdHex || !connState.peerIdBytes || b.length < 18) {
            return;
          }
          let targetHex = '';
          for (let i = 1; i <= 16; i++) targetHex += b[i].toString(16).padStart(2, '0');
          if (targetHex === connState.peerIdHex) return;

          const target = this.trackerSessions.get(targetHex);
          if (target) {
            const outFrame = new Uint8Array(b.length);
            outFrame.set(b);
            outFrame.set(connState.peerIdBytes, 1); // 送信元 ID を上書き
            try {
              target.ws.send(outFrame);
            } catch {}
          }
          return;
        }
      });

      serverWs.addEventListener('close', () => this.handleTrackerClose(serverWs));
      serverWs.addEventListener('error', () => this.handleTrackerClose(serverWs));

      return new Response(null, {
        status: 101,
        webSocket: clientWs,
      });
    }

    const pathParts = url.pathname.split('/').filter(Boolean);

    // A. 旧: 共通の SlabLeaseSet ディレクトリ (/ozzy/v2/leaseset)。★ 廃止: 置き場所は Manifest に入れ、Manifest は P2P の
    //    ファイル保管に置く。共通のサーバーに「誰がいつどの識別子を出し入れしたか」を残さない。
    if (pathParts[0] === 'ozzy' && pathParts[1] === 'v2' && pathParts[2] === 'leaseset') {
      return new Response(JSON.stringify({ error: 'GONE', reason: 'lease directory removed; manifests live in P2P file storage' }), {
        status: 410,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const slabKey = `${pathParts[1]}/${pathParts.slice(2).join('/')}`;

    if (request.method === 'PUT') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('LOW ')) {
        return new Response(JSON.stringify({ error: 'MISSING_IAS3_LOW_AUTH' }), {
          status: 401,
          headers: CORS_HEADERS,
        });
      }
      const declared = Number(request.headers.get('Content-Length') ?? '0');
      if (declared > IA_SLAB_MAX_BYTES) {
        return new Response(JSON.stringify({ error: 'SLAB_TOO_LARGE' }), { status: 413, headers: CORS_HEADERS });
      }
      const authDigest = await authDigestOf(request);
      // ★ 既にある Slab は、同じ資格情報で置いた人だけが上書きできる (旧版は LOW で始まれば誰でも上書き・削除できた)
      const owner = await this.slabOwner(slabKey);
      if (owner && owner !== authDigest) {
        return new Response(JSON.stringify({ error: 'NOT_SLAB_OWNER' }), { status: 403, headers: CORS_HEADERS });
      }
      const noindex = request.headers.get('x-archive-meta-noindex') === 'true';
      const deriveDisabled = request.headers.get('x-archive-queue-derive') === '0';
      const body = new Uint8Array(await request.arrayBuffer());
      if (body.byteLength > IA_SLAB_MAX_BYTES) {
        return new Response(JSON.stringify({ error: 'SLAB_TOO_LARGE' }), { status: 413, headers: CORS_HEADERS });
      }

      this.evictIfNeeded(body.byteLength);
      const existing = this.slabs.get(slabKey);
      if (existing) {
        this.totalBytes -= existing.data.byteLength;
      }
      const now = Date.now();
      this.slabs.set(slabKey, {
        data: body,
        createdAtMs: now,
        lastAccessedMs: now,
        noindex,
        deriveDisabled,
        authDigest,
      });
      this.deletedTombstones.delete(slabKey);
      this.totalBytes += body.byteLength;

      // ★ KV の値は 25 MiB まで。超える Slab はこの DO のメモリにだけ置く (DO が退避されると消える)
      let persisted = false;
      if (this.env && this.env.OZZY_SLAB_KV && body.byteLength <= KV_VALUE_MAX_BYTES) {
        await this.env.OZZY_SLAB_KV.put(`slab:${slabKey}`, body, { expirationTtl: 86400, metadata: { auth: authDigest } });
        persisted = true;
      }

      return new Response(
        JSON.stringify({
          ok: true,
          slabKey,
          byteLength: body.byteLength,
          noindex,
          deriveDisabled,
          persisted,
        }),
        {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        },
      );
    }

    if (request.method === 'DELETE') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('LOW ')) {
        return new Response(JSON.stringify({ error: 'MISSING_IAS3_LOW_AUTH' }), {
          status: 401,
          headers: CORS_HEADERS,
        });
      }
      const owner = await this.slabOwner(slabKey);
      if (!owner) {
        return new Response(JSON.stringify({ error: 'SLAB_NOT_FOUND' }), {
          status: 404,
          headers: CORS_HEADERS,
        });
      }
      if (owner !== (await authDigestOf(request))) {
        return new Response(JSON.stringify({ error: 'NOT_SLAB_OWNER' }), { status: 403, headers: CORS_HEADERS });
      }
      const existing = this.slabs.get(slabKey);
      if (existing) {
        this.totalBytes -= existing.data.byteLength;
        this.slabs.delete(slabKey);
      }
      this.deletedTombstones.add(slabKey);
      if (this.env && this.env.OZZY_SLAB_KV) {
        await this.env.OZZY_SLAB_KV.delete(`slab:${slabKey}`);
      }
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method === 'GET') {
      if (this.deletedTombstones.has(slabKey)) {
        return new Response(JSON.stringify({ error: 'SLAB_DELETED' }), {
          status: 404,
          headers: CORS_HEADERS,
        });
      }
      let data = null;
      const entry = this.slabs.get(slabKey);
      if (entry) {
        entry.lastAccessedMs = Date.now();
        data = entry.data;
      } else if (this.env && this.env.OZZY_SLAB_KV) {
        const kvBuf = await this.env.OZZY_SLAB_KV.get(`slab:${slabKey}`, 'arrayBuffer');
        if (kvBuf) {
          data = new Uint8Array(kvBuf);
          this.slabs.set(slabKey, {
            data,
            createdAtMs: Date.now(),
            lastAccessedMs: Date.now(),
            noindex: true,
            deriveDisabled: true,
          });
          this.totalBytes += data.byteLength;
        }
      }

      if (!data) {
        return new Response(JSON.stringify({ error: 'SLAB_NOT_FOUND' }), {
          status: 404,
          headers: CORS_HEADERS,
        });
      }

      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
        if (m) {
          const start = parseInt(m[1], 10);
          const end = m[2] ? Math.min(parseInt(m[2], 10), data.byteLength - 1) : data.byteLength - 1;
          if (start >= 0 && start <= end && start < data.byteLength) {
            const slice = data.subarray(start, end + 1);
            return new Response(slice, {
              status: 206,
              headers: {
                ...CORS_HEADERS,
                'Accept-Ranges': 'bytes',
                'Content-Type': 'application/octet-stream',
                'Content-Length': slice.byteLength.toString(),
                'Content-Range': `bytes ${start}-${end}/${data.byteLength}`,
              },
            });
          }
        }
      }

      return new Response(data, {
        status: 200,
        headers: {
          ...CORS_HEADERS,
          'Accept-Ranges': 'bytes',
          'Content-Type': 'application/octet-stream',
          'Content-Length': data.byteLength.toString(),
        },
      });
    }

    return new Response('Method Not Allowed', { status: 405, headers: CORS_HEADERS });
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const bucket = getBucket(env);
    const url = new URL(request.url);
    const cache = typeof caches !== 'undefined' && caches.default ? caches.default : null;

    // =========================================================================
    // 0. Oz WebSocket P2P トラッカー (/ws)
    // =========================================================================
    if (url.pathname === '/ws') {
      if (env && env.OZZY_VAULT_DO) {
        const doId = env.OZZY_VAULT_DO.idFromName('global-tracker-v3');
        const stub = env.OZZY_VAULT_DO.get(doId);
        return stub.fetch(request);
      }
      return new Response('Durable Objects unavailable for /ws tracker', { status: 503 });
    }

    // =========================================================================
    // 1. ステータス確認エンドポイント (/ozzy/v2/status)
    // =========================================================================
    if (url.pathname === '/ozzy/v2/status' && request.method === 'GET') {
      const slots = await ensureMetaLoaded(bucket);
      const today = currentEpochDay();
      let freeDataSlots = 0;
      for (let i = MANIFEST_POOL_SLOTS; i < TOTAL_SLOTS; i++) {
        if (slots[i].expireDay === 0 || slots[i].expireDay <= today) {
          freeDataSlots++;
        }
      }
      return new Response(
        JSON.stringify({
          ok: true,
          version: 2,
          // ★ 今の版の Ozzy 中継 (/ozzy/v2/locker-proxy) が使える印。アプリは自分の Worker の設定時にこれを確かめる
          relay: true,
          relayVersion: 1,
          mode: env && env.OZZY_VAULT_DO ? 'ias3-durable-object+kv-cardless' : 'ias3-edge-cache-cardless',
          totalSlots: TOTAL_SLOTS,
          manifestPoolSlots: MANIFEST_POOL_SLOTS,
          dataPoolSlots: TOTAL_SLOTS - MANIFEST_POOL_SLOTS,
          freeDataSlots,
          expectedChunkBytes: CHUNK_BYTES,
          classACount,
          classBCount,
          iaSlabStats: {
            activeSlabs: iaSlabs.size,
            totalBytes: iaSlabTotalBytes,
            putCount: iaPutCount,
            rangeGetCount: iaRangeGetCount,
            deleteCount: iaDeleteCount,
          },
        }),
        {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        },
      );
    }

    // =========================================================================
    // 1b. 旧: 共通の SlabLeaseSet ディレクトリ (/ozzy/v2/leaseset)。★ 廃止 (置き場所は Manifest に入れ、P2P に置く)
    // =========================================================================
    const pathParts = url.pathname.split('/').filter(Boolean);
    if (pathParts[0] === 'ozzy' && pathParts[1] === 'v2' && pathParts[2] === 'leaseset') {
      return new Response(JSON.stringify({ error: 'GONE', reason: 'lease directory removed; manifests live in P2P file storage' }), {
        status: 410,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // =========================================================================
    // 1c. 海外 7 社無記名ロッカー向け CORS ブラインド・リレー (/ozzy/v2/locker-proxy)
    // =========================================================================
    if (url.pathname === '/ozzy/v2/locker-proxy' && request.method === 'POST') {
      const targetUrlStr = request.headers.get('X-Ozzy-Target-Url') ?? '';
      const targetMethod = (request.headers.get('X-Ozzy-Target-Method') ?? 'GET').toUpperCase();
      let targetUrl;
      try {
        targetUrl = new URL(targetUrlStr);
      } catch {
        return new Response(JSON.stringify({ error: 'INVALID_TARGET_URL' }), {
          status: 400,
          headers: CORS_HEADERS,
        });
      }
      if (targetUrl.protocol !== 'https:' || targetUrl.port !== '' || !isAllowedOverseasLockerHost(targetUrl.hostname)) {
        return new Response(JSON.stringify({ error: 'DISALLOWED_LOCKER_HOST', host: targetUrl.hostname }), {
          status: 403,
          headers: CORS_HEADERS,
        });
      }
      if (!['GET', 'HEAD', 'POST', 'PUT', 'DELETE'].includes(targetMethod)) {
        return new Response(JSON.stringify({ error: 'DISALLOWED_METHOD' }), { status: 405, headers: CORS_HEADERS });
      }
      // Workers の受信の上限 (無料プラン 100 MB) より手前で断る
      if (Number(request.headers.get('Content-Length') ?? '0') > 100 * 1024 * 1024) {
        return new Response(JSON.stringify({ error: 'BODY_TOO_LARGE' }), { status: 413, headers: CORS_HEADERS });
      }
      const strippedHeaderNames = new Set([
        'cf-connecting-ip',
        'true-client-ip',
        'x-forwarded-for',
        'x-real-ip',
        'forwarded',
        'via',
        'referer',
        'origin',
        'host',
      ]);
      const forwardHeaders = new Headers();
      const rawCustomHeaders = request.headers.get('X-Ozzy-Target-Headers');
      if (rawCustomHeaders) {
        try {
          const parsed = JSON.parse(rawCustomHeaders);
          for (const [k, v] of Object.entries(parsed)) {
            if (typeof v === 'string' && !strippedHeaderNames.has(k.toLowerCase())) {
              forwardHeaders.set(k, v);
            }
          }
        } catch {
          // ignore malformed custom header json
        }
      }
      const hasBody = targetMethod !== 'GET' && targetMethod !== 'HEAD';
      const bodyBuf = hasBody ? await request.arrayBuffer() : undefined;
      try {
        const upstreamRes = await fetch(targetUrl.toString(), {
          method: targetMethod,
          headers: forwardHeaders,
          body: hasBody && bodyBuf && bodyBuf.byteLength > 0 ? bodyBuf : undefined,
        });
        const respHeaders = new Headers(CORS_HEADERS);
        const ct = upstreamRes.headers.get('Content-Type');
        if (ct) respHeaders.set('Content-Type', ct);
        const cr = upstreamRes.headers.get('Content-Range');
        if (cr) respHeaders.set('Content-Range', cr);
        const xtok = upstreamRes.headers.get('X-Token');
        if (xtok) respHeaders.set('X-Token', xtok);
        respHeaders.set('X-Ozzy-Proxied-Status', String(upstreamRes.status));
        return new Response(upstreamRes.body, {
          status: upstreamRes.status,
          headers: respHeaders,
        });
      } catch {
        return new Response(JSON.stringify({ error: 'UPSTREAM_LOCKER_UNREACHABLE' }), {
          status: 502,
          headers: CORS_HEADERS,
        });
      }
    }
    if (
      pathParts.length >= 3 &&
      (pathParts[0] === 'ias3' || pathParts[0] === 'download')
    ) {
      if (env && env.OZZY_VAULT_DO) {
        const doId = env.OZZY_VAULT_DO.idFromName(pathParts[1]);
        const stub = env.OZZY_VAULT_DO.get(doId);
        return stub.fetch(request);
      }
      const slabKey = `${pathParts[1]}/${pathParts.slice(2).join('/')}`;
      const cacheKeyUrl = new URL(`https://ozzy-slab-cache.internal/${slabKey}`);

      // その Slab を置いた資格情報の指紋 (このIsolate のメモリ → Edge Cache のヘッダ)
      const slabOwner = async () => {
        const mem = iaSlabs.get(slabKey);
        if (mem && mem.authDigest) return mem.authDigest;
        if (cache) {
          const cached = await cache.match(cacheKeyUrl.toString());
          if (cached) return cached.headers.get('X-Ozzy-Auth-Digest');
        }
        return null;
      };

      if (request.method === 'PUT') {
        const auth = request.headers.get('Authorization') ?? '';
        if (!auth.startsWith('LOW ')) {
          return new Response(JSON.stringify({ error: 'MISSING_IAS3_LOW_AUTH' }), {
            status: 401,
            headers: CORS_HEADERS,
          });
        }
        if (Number(request.headers.get('Content-Length') ?? '0') > IA_SLAB_MAX_BYTES) {
          return new Response(JSON.stringify({ error: 'SLAB_TOO_LARGE' }), { status: 413, headers: CORS_HEADERS });
        }
        const authDigest = await authDigestOf(request);
        const owner = await slabOwner();
        if (owner && owner !== authDigest) {
          return new Response(JSON.stringify({ error: 'NOT_SLAB_OWNER' }), { status: 403, headers: CORS_HEADERS });
        }
        const noindex = request.headers.get('x-archive-meta-noindex') === 'true';
        const deriveDisabled = request.headers.get('x-archive-queue-derive') === '0';
        const body = new Uint8Array(await request.arrayBuffer());
        if (body.byteLength > IA_SLAB_MAX_BYTES) {
          return new Response(JSON.stringify({ error: 'SLAB_TOO_LARGE' }), { status: 413, headers: CORS_HEADERS });
        }

        evictOldestSlabsIfNeeded(body.byteLength);
        const existing = iaSlabs.get(slabKey);
        if (existing) {
          iaSlabTotalBytes -= existing.data.byteLength;
        }
        const now = Date.now();
        iaSlabs.set(slabKey, {
          data: body,
          createdAtMs: now,
          lastAccessedMs: now,
          noindex,
          deriveDisabled,
          authDigest,
        });
        iaSlabTotalBytes += body.byteLength;
        iaPutCount++;

        if (cache) {
          const cacheRes = new Response(body, {
            status: 200,
            headers: {
              'Content-Type': 'application/octet-stream',
              'Content-Length': body.byteLength.toString(),
              'Cache-Control': 'public, max-age=86400',
              'X-Ozzy-Slab-Noindex': String(noindex),
              'X-Ozzy-Slab-Derive': deriveDisabled ? '0' : '1',
              'X-Ozzy-Auth-Digest': authDigest,
            },
          });
          await cache.put(cacheKeyUrl.toString(), cacheRes);
        }

        return new Response(
          JSON.stringify({
            ok: true,
            slabKey,
            byteLength: body.byteLength,
            noindex,
            deriveDisabled,
          }),
          {
            status: 200,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          },
        );
      }

      if (request.method === 'DELETE') {
        const auth = request.headers.get('Authorization') ?? '';
        if (!auth.startsWith('LOW ')) {
          return new Response(JSON.stringify({ error: 'MISSING_IAS3_LOW_AUTH' }), {
            status: 401,
            headers: CORS_HEADERS,
          });
        }
        const owner = await slabOwner();
        if (!owner) {
          return new Response(JSON.stringify({ error: 'SLAB_NOT_FOUND' }), {
            status: 404,
            headers: CORS_HEADERS,
          });
        }
        if (owner !== (await authDigestOf(request))) {
          return new Response(JSON.stringify({ error: 'NOT_SLAB_OWNER' }), { status: 403, headers: CORS_HEADERS });
        }
        const existing = iaSlabs.get(slabKey);
        if (existing) {
          iaSlabTotalBytes -= existing.data.byteLength;
          iaSlabs.delete(slabKey);
        }
        if (cache) await cache.delete(cacheKeyUrl.toString());
        iaDeleteCount++;
        return new Response(null, { status: 204, headers: CORS_HEADERS });
      }

      if (request.method === 'GET') {
        let data = null;
        if (cache) {
          // 複数 Isolate 間で一貫性を保つため Edge Cache (caches.default) を正本として参照
          const cached = await cache.match(cacheKeyUrl.toString());
          if (cached) {
            data = new Uint8Array(await cached.arrayBuffer());
          } else if (iaSlabs.has(slabKey)) {
            // 別 Isolate で DELETE 済みの場合はローカル RAM マップからも即パージ
            const stale = iaSlabs.get(slabKey);
            iaSlabTotalBytes -= stale.data.byteLength;
            iaSlabs.delete(slabKey);
          }
        } else {
          const entry = iaSlabs.get(slabKey);
          if (entry) {
            entry.lastAccessedMs = Date.now();
            data = entry.data;
          }
        }

        if (!data) {
          return new Response(JSON.stringify({ error: 'SLAB_NOT_FOUND' }), {
            status: 404,
            headers: CORS_HEADERS,
          });
        }

        const rangeHeader = request.headers.get('Range');
        if (rangeHeader) {
          const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
          if (m) {
            const start = parseInt(m[1], 10);
            const end = m[2] ? Math.min(parseInt(m[2], 10), data.byteLength - 1) : data.byteLength - 1;
            if (start >= 0 && start <= end && start < data.byteLength) {
              const slice = data.subarray(start, end + 1);
              iaRangeGetCount++;
              return new Response(slice, {
                status: 206,
                headers: {
                  ...CORS_HEADERS,
                  'Accept-Ranges': 'bytes',
                  'Content-Type': 'application/octet-stream',
                  'Content-Length': slice.byteLength.toString(),
                  'Content-Range': `bytes ${start}-${end}/${data.byteLength}`,
                },
              });
            }
          }
        }

        return new Response(data, {
          status: 200,
          headers: {
            ...CORS_HEADERS,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/octet-stream',
            'Content-Length': data.byteLength.toString(),
          },
        });
      }
    }

    // =========================================================================
    // 3. Gatekeeper 単一チャンク PUT/GET/TOUCH エンドポイント (/ozzy/v2/chunk)
    // =========================================================================
    if (url.pathname === '/ozzy/v2/chunk' && request.method === 'PUT') {
      if (classACount >= MONTHLY_CLASS_A_CAP) {
        return new Response(JSON.stringify({ error: 'CLASS_A_QUOTA_CAP_REACHED' }), {
          status: 429,
          headers: CORS_HEADERS,
        });
      }
      const isManifest = (request.headers.get('X-Ozzy-Pool') ?? 'data').toLowerCase() === 'manifest';
      const rawCandidates = (request.headers.get('X-Ozzy-Candidates') ?? '')
        .split(',')
        .map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isInteger(n));
      const candidates = Array.from(new Set(rawCandidates));
      const minSlot = isManifest ? 0 : MANIFEST_POOL_SLOTS;
      const maxSlot = isManifest ? MANIFEST_POOL_SLOTS - 1 : TOTAL_SLOTS - 1;
      if (candidates.length === 0 || rawCandidates.length > 4 || candidates.some(c => c < minSlot || c > maxSlot)) {
        return new Response(JSON.stringify({ error: 'INVALID_CANDIDATES' }), {
          status: 403,
          headers: CORS_HEADERS,
        });
      }
      const body = new Uint8Array(await request.arrayBuffer());
      if (body.byteLength !== CHUNK_BYTES && body.byteLength !== 65536) {
        return new Response(JSON.stringify({ error: 'INVALID_CHUNK_SIZE', actual: body.byteLength }), {
          status: 400,
          headers: CORS_HEADERS,
        });
      }
      const tag = body.slice(0, TAG_BYTES);
      if (isAllZeroTag(tag)) {
        return new Response(JSON.stringify({ error: 'ZERO_TAG_FORBIDDEN' }), {
          status: 400,
          headers: CORS_HEADERS,
        });
      }
      const slots = await ensureMetaLoaded(bucket);
      const today = currentEpochDay();

      let targetSlot = -1;
      for (const c of candidates) {
        if (slots[c].expireDay > 0 && bytesEqual(slots[c].tag, tag)) {
          targetSlot = c;
          break;
        }
      }
      if (targetSlot === -1) {
        const victim = selectVictimSlot(candidates, slots, today);
        if (!victim) {
          return new Response(JSON.stringify({ error: 'SLOT_HOT_FULL' }), {
            status: 409,
            headers: CORS_HEADERS,
          });
        }
        targetSlot = victim.slotId;
      }

      const ttlDaysRaw = parseInt(request.headers.get('X-Ozzy-TTL-Days') ?? '90', 10);
      const ttlDays = Number.isInteger(ttlDaysRaw) ? Math.min(Math.max(ttlDaysRaw, 60), 120) : 90;

      classACount++;
      await bucket.put(`ozzy/b/${targetSlot.toString(16).padStart(4, '0')}`, body);
      slots[targetSlot] = { tag, expireDay: today + ttlDays, lastFetchedDay: 0 };
      if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(maybeFlushMeta(bucket));
      }
      return new Response(JSON.stringify({ ok: true, slotId: targetSlot, tag: toHex(tag) }), {
        status: 200,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname === '/ozzy/v2/chunk' && request.method === 'GET') {
      if (classBCount >= MONTHLY_CLASS_B_CAP) {
        return new Response(JSON.stringify({ error: 'CLASS_B_QUOTA_CAP_REACHED' }), {
          status: 429,
          headers: CORS_HEADERS,
        });
      }
      const expectedTag = fromHex(url.searchParams.get('tag') ?? request.headers.get('X-Ozzy-Tag') ?? '');
      if (!expectedTag || expectedTag.length !== TAG_BYTES || isAllZeroTag(expectedTag)) {
        return new Response(JSON.stringify({ error: 'INVALID_TAG' }), { status: 400, headers: CORS_HEADERS });
      }
      const candidates = (url.searchParams.get('candidates') ?? request.headers.get('X-Ozzy-Candidates') ?? '')
        .split(',')
        .map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isInteger(n) && n >= 0 && n < TOTAL_SLOTS);
      const slots = await ensureMetaLoaded(bucket);
      const today = currentEpochDay();
      const matchedSlot = candidates.find(c => slots[c].expireDay > 0 && bytesEqual(slots[c].tag, expectedTag));
      if (matchedSlot === undefined) {
        return new Response(JSON.stringify({ error: 'CHUNK_NOT_FOUND' }), { status: 404, headers: CORS_HEADERS });
      }

      const rangeHeader = request.headers.get('Range');
      let rangeOpt = undefined;
      let startByte = 0;
      let endByte = CHUNK_BYTES - 1;
      let isPartial = false;
      if (rangeHeader) {
        const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
        if (m) {
          startByte = parseInt(m[1], 10);
          endByte = m[2] ? Math.min(parseInt(m[2], 10), CHUNK_BYTES - 1) : CHUNK_BYTES - 1;
          if (startByte >= 0 && startByte <= endByte && startByte < CHUNK_BYTES) {
            rangeOpt = { offset: startByte, length: endByte - startByte + 1 };
            isPartial = true;
          }
        }
      }

      classBCount++;
      const obj = await bucket.get(
        `ozzy/b/${matchedSlot.toString(16).padStart(4, '0')}`,
        rangeOpt ? { range: rangeOpt } : undefined,
      );
      if (!obj) {
        return new Response(JSON.stringify({ error: 'OBJECT_MISSING' }), { status: 404, headers: CORS_HEADERS });
      }
      slots[matchedSlot].lastFetchedDay = today;
      slots[matchedSlot].expireDay = Math.max(slots[matchedSlot].expireDay, today + TOUCH_EXTEND_DAYS);
      const headers = {
        ...CORS_HEADERS,
        'Content-Type': 'application/octet-stream',
        'X-Ozzy-Slot-Id': matchedSlot.toString(),
      };
      if (isPartial) {
        headers['Content-Range'] = `bytes ${startByte}-${endByte}/${CHUNK_BYTES}`;
      }
      return new Response(obj.body, {
        status: isPartial ? 206 : 200,
        headers,
      });
    }

    if (url.pathname === '/ozzy/v2/touch' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      if (!body || !Array.isArray(body.candidates) || typeof body.tag !== 'string') {
        return new Response(JSON.stringify({ error: 'INVALID_TOUCH_PAYLOAD' }), { status: 400, headers: CORS_HEADERS });
      }
      const expectedTag = fromHex(body.tag);
      if (!expectedTag || expectedTag.length !== TAG_BYTES || isAllZeroTag(expectedTag)) {
        return new Response(JSON.stringify({ error: 'INVALID_TAG' }), { status: 400, headers: CORS_HEADERS });
      }
      const slots = await ensureMetaLoaded(bucket);
      const today = currentEpochDay();
      for (const c of body.candidates) {
        if (Number.isInteger(c) && c >= 0 && c < TOTAL_SLOTS && slots[c].expireDay > 0 && bytesEqual(slots[c].tag, expectedTag)) {
          slots[c].lastFetchedDay = today;
          slots[c].expireDay = Math.max(slots[c].expireDay, today + TOUCH_EXTEND_DAYS);
          return new Response(
            JSON.stringify({ ok: true, slotId: c, expireDay: slots[c].expireDay, lastFetchedDay: slots[c].lastFetchedDay }),
            { status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } },
          );
        }
      }
      return new Response(JSON.stringify({ error: 'CHUNK_NOT_FOUND' }), { status: 404, headers: CORS_HEADERS });
    }

    return new Response('Not Found', { status: 404, headers: CORS_HEADERS });
  },
};
