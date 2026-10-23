import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity, type JoinBinding } from '../../src/crypto/NodeIdentity';
import { extractFingerprint } from '../../src/network/WebRTCPeer';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };

describe('JOIN v4: 接続への束縛 (C6)', () => {
  let signer: NodeIdentity;
  let verifierId: string;
  let otherVerifierId: string;

  beforeAll(async () => {
    await sodiumReady;
    signer = await NodeIdentity.mine(FAST);
    verifierId = (await NodeIdentity.mine(FAST)).peerId;
    otherVerifierId = (await NodeIdentity.mine(FAST)).peerId;
  });

  const binding = (over: Partial<JoinBinding> = {}): JoinBinding => ({
    verifierId,
    signerFingerprint: 'sha-256 AA:BB',
    verifierFingerprint: 'sha-256 CC:DD',
    ...over,
  });

  it('同じ接続文脈なら受理される', () => {
    const c = NodeIdentity.newChallenge();
    const claim = signer.signClaim(c, binding());
    expect(NodeIdentity.verifySignedClaim(claim, c, binding(), FAST)).toBe(true);
  });

  it('別の検証者向けに作られた署名は受理しない', () => {
    const c = NodeIdentity.newChallenge();
    const claim = signer.signClaim(c, binding({ verifierId: otherVerifierId }));
    expect(NodeIdentity.verifySignedClaim(claim, c, binding(), FAST)).toBe(false);
  });

  it('DTLS 指紋が食い違う (別の接続で得た) 署名は受理しない', () => {
    const c = NodeIdentity.newChallenge();
    const claim = signer.signClaim(c, binding({ signerFingerprint: 'sha-256 EE:FF' }));
    expect(NodeIdentity.verifySignedClaim(claim, c, binding(), FAST)).toBe(false);
    const claim2 = signer.signClaim(c, binding({ verifierFingerprint: 'sha-256 11:22' }));
    expect(NodeIdentity.verifySignedClaim(claim2, c, binding(), FAST)).toBe(false);
  });

  it('旧形式 (challenge だけへの署名) は受理しない', () => {
    const c = NodeIdentity.newChallenge();
    const secret = signer.exportSecret();
    const legacy = new Uint8Array([...new TextEncoder().encode('OZ/v3/join'), ...c]);
    const claim = { ...signer.claim(), challenge: c, signature: sodium.crypto_sign_detached(legacy, secret.privkey) };
    expect(NodeIdentity.verifySignedClaim(claim, c, binding(), FAST)).toBe(false);
  });

  it('固定長以外の challenge には署名しない', () => {
    expect(() => signer.signClaim(new Uint8Array(5), binding())).toThrow(RangeError);
  });

  it('SDP から a=fingerprint を正規化して取り出す', () => {
    const sdp = 'v=0\r\na=fingerprint:SHA-256 ab:cd\r\nm=application\r\na=fingerprint:sha-256 AB:CD\r\n';
    expect(extractFingerprint(sdp)).toBe('sha-256 AB:CD');
    expect(extractFingerprint('v=0\r\n')).toBe('');
    expect(extractFingerprint(undefined)).toBe('');
  });
});
