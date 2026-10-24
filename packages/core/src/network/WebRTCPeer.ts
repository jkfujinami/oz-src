import type { IPeerConnection, PeerId } from '../types';
import { RingPosition } from './RingPosition';
import { ChunkedSender } from './stream/ChunkedSender';
import { ChunkedReceiver } from './stream/ChunkedReceiver';
import { createLogger } from '../common/Logger';
import { netGroupOf, originKeyOf, ORIGIN_LAN, ORIGIN_UNKNOWN } from './NetGroup';

const log = createLogger('net.webrtc');

interface WebRTCPeerOptions {
  localId: string;
  remoteId: string;
  initiator: boolean;
  onSignal: (payload: any) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onData: (data: Uint8Array | string) => void;
  /**
   * STUN サーバ (トラッカー由来)。★ 第三者の STUN は使わない (IP と接続時刻が運営者に渡る)。
   * 空なら host 候補だけで繋ぐ。
   */
  iceServers?: RTCIceServer[];
}

export class WebRTCPeer implements IPeerConnection {
  private pc: RTCPeerConnection;
  private channel?: RTCDataChannel;
  private chunkedSender = new ChunkedSender();
  private chunkedReceiver: ChunkedReceiver;

  public readonly peerId: PeerId;
  /**
   * リング座標。peerId から導出した値であって、相手の申告ではない。
   * 書き換え可能な public フィールドではなく readonly にしてある。
   */
  public readonly position: number;
  public rtt: number = 0;

  private _connected = false;
  private _connecting = true;
  private _verified = false;
  private _pubkey: Uint8Array | null = null;
  private _powCounter: number | null = null;
  private _verifiedAt: number | null = null;
  private _netGroup: string | null = null;
  private _origin: string | null = null;
  private _localOrigins: string[] = [];

  /**
   * 接続の向き。outbound = 自分で選んで張りに行った接続、inbound = 相手から来た接続。
   *
   * Sybil は inbound なら好きなだけ送り込めるが、自分が選ぶ outbound の相手は
   * 自由にできない。次数の調整と Guard 選びでこの違いを使う。
   */
  public readonly direction: 'outbound' | 'inbound';
  /** 相手に送ったチャレンジ。JOIN の署名検証に使う */
  private _challenge: Uint8Array | null = null;
  private opts: WebRTCPeerOptions;

  public get isConnected(): boolean {
    return this._connected;
  }

  public get isConnecting(): boolean {
    return this._connecting;
  }

  /** HELLO/JOIN のハンドシェイクで Bound Identity を検証済みか */
  public get isVerified(): boolean {
    return this._verified;
  }

  /** 検証済みの Ed25519 公開鍵 */
  public get pubkey(): Uint8Array | null {
    return this._pubkey;
  }

  /** 本人確認 (JOIN) が済んだ時刻。この接続をどれだけ長く観測しているかの基準 */
  public get verifiedAt(): number | null {
    return this._verifiedAt;
  }

  /** ネットワーク上の出所の区分 ({@link netGroupOf})。未取得なら null */
  public get netGroup(): string | null {
    return this._netGroup;
  }

  /** 相手の出所の鍵 ({@link originKeyOf})。経路の各段が同じ家にならないように比べる。未取得なら null */
  public get origin(): string | null {
    return this._origin;
  }

  /**
   * この接続で分かった自分の公開側の出所 (STUN などで分かった、外から見えている自分の鍵)。
   * 私設アドレスしか分からなければ空。
   */
  public get localOrigins(): readonly string[] {
    return this._localOrigins;
  }

  /**
   * 確定した経路 (selected candidate pair) から相手の出所の区分を求める。
   * IP そのものは保持しない。取れなければ 'unknown'。
   */
  public async resolveNetGroup(): Promise<string> {
    if (this._netGroup) return this._netGroup;
    let group = 'unknown';
    try {
      const stats: any = await this.pc.getStats();
      const all = new Map<string, any>();
      stats.forEach((s: any) => all.set(s.id, s));

      let pair: any = null;
      for (const s of all.values()) {
        if (s.type === 'transport' && s.selectedCandidatePairId) pair = all.get(s.selectedCandidatePairId);
      }
      if (!pair) {
        for (const s of all.values()) {
          if (s.type === 'candidate-pair' && s.state === 'succeeded' && (s.nominated || s.selected)) pair = s;
        }
      }
      const remote = pair ? all.get(pair.remoteCandidateId) : null;
      if (remote) {
        group = netGroupOf(remote.address ?? remote.ip, remote.candidateType);
        this._origin = originKeyOf(remote.address ?? remote.ip, remote.candidateType);
      }
      // 自分の公開側: 使っている経路の自分側と、STUN で分かった自分の候補 (srflx / prflx)
      const mine = new Set<string>();
      const local = pair ? all.get(pair.localCandidateId) : null;
      if (local) mine.add(originKeyOf(local.address ?? local.ip, local.candidateType));
      for (const c of all.values()) {
        if (c.type === 'local-candidate' && (c.candidateType === 'srflx' || c.candidateType === 'prflx')) {
          mine.add(originKeyOf(c.address ?? c.ip, c.candidateType));
        }
      }
      mine.delete(ORIGIN_LAN);
      mine.delete(ORIGIN_UNKNOWN);
      this._localOrigins = [...mine];
    } catch {
      // getStats が使えない環境では 'unknown' のまま
    }
    this._netGroup = group;
    if (this._origin === null) this._origin = ORIGIN_UNKNOWN;
    return group;
  }

  /** 検証済みの NodeId PoW の解 (PEX で隣人の claim を紹介するために保持する) */
  public get powCounter(): number | null {
    return this._powCounter;
  }

  public get challenge(): Uint8Array | null {
    return this._challenge;
  }

  constructor(opts: WebRTCPeerOptions) {
    this.opts = opts;
    this.peerId = opts.remoteId;
    this.direction = opts.initiator ? 'outbound' : 'inbound';
    // 座標は peerId の純粋関数。相手からもらった数値は一切使わない。
    this.position = RingPosition.forPeer(opts.remoteId);

    this.chunkedReceiver = new ChunkedReceiver((assembled) => {
      this.opts.onData(new Uint8Array(assembled));
    });

    const iceServers = opts.iceServers ?? [];

    this.pc = new RTCPeerConnection({
      iceServers,
      iceCandidatePoolSize: 4,
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require',
      iceTransportPolicy: 'all',
    });

    this.setupEvents();

    if (opts.initiator) {
      // DataChannelの作成 (送信者側)
      this.channel = this.pc.createDataChannel('oz', {
        ordered: true,
      });
      this.setupChannelEvents(this.channel);
      this.createOffer();
    }
  }

  private setupEvents(): void {
    this.pc.onicecandidate = (event) => {
      log.debug(`[WebRTCPeer ${this.peerId}] onicecandidate:`, event.candidate ? 'has candidate' : 'null (done)');
      if (event.candidate) {
        // mDNS (.local) 候補のフィルタリング:
        // WAN 越えの P2P において xxxx.local は相手先ルーターで解決不能であり、
        // タイムアウト待ちによる ICE 接続遅延を招くためシグナリングから除外する
        if (event.candidate.candidate && event.candidate.candidate.includes('.local')) {
          log.debug(`[WebRTCPeer ${this.peerId}] filtering out mDNS candidate (.local)`);
          return;
        }
        this.opts.onSignal(event.candidate);
      }
    };

    this.pc.ondatachannel = (event) => {
      // 着信側のDataChannel受信
      this.channel = event.channel;
      this.setupChannelEvents(this.channel);
    };

    this.pc.oniceconnectionstatechange = () => {
      const state = this.pc.iceConnectionState;
      log.debug(`[WebRTCPeer ${this.peerId}] iceConnectionState:`, state);
      if (state === 'disconnected' || state === 'failed') {
        this._connected = false;
        this._connecting = false;
        this.opts.onDisconnect();
      }
    };
  }

  private setupChannelEvents(channel: RTCDataChannel): void {
    channel.binaryType = 'arraybuffer';

    channel.onopen = () => {
      log.debug(`DataChannel open with ${this.peerId}`);
      this._connected = true;
      this._connecting = false;
      this.opts.onConnect();
    };

    channel.onclose = () => {
      log.debug(`DataChannel closed with ${this.peerId}`);
      this._connected = false;
      this._connecting = false;
      this.opts.onDisconnect();
    };

    channel.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        this.chunkedReceiver.receive(event.data);
      } else {
        this.opts.onData(event.data);
      }
    };
  }

  private optimizeSdp(desc: RTCSessionDescription | null): { type: RTCSdpType; sdp: string } | null {
    if (!desc || !desc.sdp) return desc;
    let sdp = desc.sdp;
    if (!sdp.includes('a=max-message-size')) {
      sdp = sdp.trimEnd() + '\r\na=max-message-size:16384\r\n';
    }
    return { type: desc.type, sdp };
  }

  private async createOffer(): Promise<void> {
    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      
      this.opts.onSignal(this.optimizeSdp(this.pc.localDescription));
    } catch (e) {
      log.error(`Error creating offer`, e);
    }
  }

  private pendingCandidates: RTCIceCandidateInit[] = [];

  public async signal(data: any): Promise<void> {
    log.debug(`[WebRTCPeer ${this.peerId}] signal() called with:`, data.type);
    try {
      if (data.sdp) {
        log.debug(`[WebRTCPeer ${this.peerId}] Setting remote description (${data.sdp.type})`);
        const sdp = new RTCSessionDescription(data.sdp);
        await this.pc.setRemoteDescription(sdp);
        
        if (sdp.type === 'offer') {
          log.debug(`[WebRTCPeer ${this.peerId}] Creating answer`);
          const answer = await this.pc.createAnswer();
          await this.pc.setLocalDescription(answer);

          // 返信のシグナリング (MTU 最適化適用)
          this.opts.onSignal(this.optimizeSdp(this.pc.localDescription));
        }
        
        // バッファされたICE Candidateを処理
        log.debug(`[WebRTCPeer ${this.peerId}] Processing ${this.pendingCandidates.length} buffered candidates`);
        for (const candidate of this.pendingCandidates) {
          await this.pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(e => log.error(e));
        }
        this.pendingCandidates = [];

      } else if (data.candidate) {
        log.debug(`[WebRTCPeer ${this.peerId}] Received ICE candidate`);
        if (this.pc.remoteDescription) {
          const candidate = new RTCIceCandidate(data.candidate);
          await this.pc.addIceCandidate(candidate).catch(e => log.error(e));
        } else {
          log.warn(`[WebRTCPeer ${this.peerId}] remoteDescription not set yet, buffering candidate!`);
          this.pendingCandidates.push(data.candidate);
        }
      }
    } catch (e) {
      log.error(`[WebRTCPeer ${this.peerId}] Error handling signal`, e);
    }
  }

  /** DataChannel の送信待ちのバイト数 (送り手が送出を絞るのに使う) */
  public get bufferedAmount(): number {
    return this.channel?.bufferedAmount ?? 0;
  }

  public send(msg: Uint8Array | string): void {
    if (!this.channel || this.channel.readyState !== 'open') return;
    if (typeof msg === 'string') {
      this.channel.send(msg);
      return;
    }
    // Use ChunkedSender: messages <= 4KB go through in one send(),
    // larger messages (e.g. DHT sync responses) are split into 4KB chunks.
    this.chunkedSender.send(this.channel, msg).catch((e) => {
      log.error(`ChunkedSend failed`, e);
    });
  }

  /**
   * この接続の DTLS 証明書フィンガープリント (SDP の a=fingerprint 行)。
   *
   * JOIN 署名をこの接続に束縛するために使う ({@link JoinBinding})。
   * DataChannel が開いた時点で local / remote の両 SDP は確定している。
   * 取れない場合は空文字を返す (呼び出し側が fail-closed で扱う)。
   */
  public dtlsFingerprints(): { local: string; remote: string } {
    return {
      local: extractFingerprint(this.pc.localDescription?.sdp),
      remote: extractFingerprint(this.pc.remoteDescription?.sdp),
    };
  }

  /** 送出したチャレンジを記録する (HELLO 送信時) */
  public setChallenge(challenge: Uint8Array) {
    this._challenge = challenge;
  }

  /** Bound Identity の検証に成功した印を付ける */
  public markVerified(pubkey?: Uint8Array, powCounter?: number) {
    this._verified = true;
    this._verifiedAt = Date.now();
    if (pubkey) this._pubkey = pubkey;
    if (typeof powCounter === 'number') this._powCounter = powCounter;
  }

  public close(): void {
    this._connected = false;
    this._connecting = false;
    this.chunkedReceiver.destroy();
    if (this.channel) this.channel.close();
    this.pc.close();
  }
}

/**
 * SDP から a=fingerprint を取り出して正規化する。
 * 複数行ある場合 (セッション / メディア単位) は重複を除いてソート連結する。
 */
export function extractFingerprint(sdp: string | undefined | null): string {
  if (typeof sdp !== 'string') return '';
  const found = new Set<string>();
  for (const m of sdp.matchAll(/^a=fingerprint:\s*(\S+)\s+([0-9A-Fa-f:]+)\s*$/gm)) {
    found.add(`${m[1].toLowerCase()} ${m[2].toUpperCase()}`);
  }
  return Array.from(found).sort().join(',');
}
