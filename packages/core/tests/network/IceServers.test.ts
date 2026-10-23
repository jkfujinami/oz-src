import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { deriveStunFromTracker, parseIceServers, resolveIceServers } from '../../src/network/IceServers';

describe('ICE サーバの決め方', () => {
  it('トラッカー URL のホストから stun:<host>:3478 を導く', () => {
    expect(deriveStunFromTracker('wss://host.example.org:443/ws')).toBe('stun:host.example.org:3478');
    expect(deriveStunFromTracker('wss://host.example.org/ws')).toBe('stun:host.example.org:3478');
    expect(deriveStunFromTracker('ws://127.0.0.1:8080/ws')).toBe('stun:127.0.0.1:3478');
    expect(deriveStunFromTracker('wss://[2001:db8::1]:8443/ws')).toBe('stun:[2001:db8::1]:3478');
    expect(deriveStunFromTracker(null)).toBeNull();
    expect(deriveStunFromTracker('not a url')).toBeNull();
  });

  it('明示の設定があればそれを使い、無ければ安定した Multi-AS STUN クラスタを使用する', () => {
    expect(resolveIceServers(['stun:s.example.org:19302'], 'wss://t.example.org/ws')).toEqual([{ urls: 'stun:s.example.org:19302' }]);
    expect(resolveIceServers([], 'wss://t.example.org/ws')).toEqual([
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
    ]);
    expect(resolveIceServers(null, null)).toEqual([
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
    ]);
  });

  it('設定の検証: stun: のみ、turn: は拒否', () => {
    expect(parseIceServers('stun:a.example.org, stun:b.example.org:3479')).toEqual({ ok: true, servers: ['stun:a.example.org', 'stun:b.example.org:3479'] });
    expect(parseIceServers('')).toEqual({ ok: true, servers: [] });
    expect(parseIceServers(undefined)).toEqual({ ok: true, servers: [] });
    expect(parseIceServers('turn:user:pass@t.example.org').ok).toBe(false);
    expect(parseIceServers('turns:t.example.org').ok).toBe(false);
    expect(parseIceServers('stun:a.example.org?x=1').ok).toBe(false);
    expect(parseIceServers('stun:a.example.org:99999').ok).toBe(false);
    expect(parseIceServers('a.example.org').ok).toBe(false);
    expect(parseIceServers('stun:a,stun:b,stun:c,stun:d,stun:e').ok).toBe(false);
  });

  it('デフォルトの STUN は Google Anycast クラスタが設定されている', () => {
    const servers = resolveIceServers(null);
    expect(servers[0].urls).toContain('stun:stun.l.google.com:19302');
  });
});
