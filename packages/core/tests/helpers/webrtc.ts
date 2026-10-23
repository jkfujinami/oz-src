let pcSeq = 0;
const registry = new Map<string, FakeRTCPeerConnection>();

class FakeDataChannel {
  public readyState: 'connecting' | 'open' | 'closed' = 'connecting';
  public binaryType = 'arraybuffer';
  public bufferedAmount = 0;
  public onopen: (() => void) | null = null;
  public onclose: (() => void) | null = null;
  public onmessage: ((e: { data: any }) => void) | null = null;
  public peer: FakeDataChannel | null = null;
  public dropAll = false;

  constructor(public readonly label: string) {}

  send(data: any): void {
    if (this.readyState !== 'open' || !this.peer || this.dropAll) return;
    const bytes = data instanceof Uint8Array
      ? data.slice()
      : typeof data === 'string'
        ? new TextEncoder().encode(data)
        : new Uint8Array(data);
    const target = this.peer;
    queueMicrotask(() => {
      if (target.readyState === 'open') {
        target.onmessage?.({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
      }
    });
  }

  open(): void {
    if (this.readyState === 'open') return;
    this.readyState = 'open';
    queueMicrotask(() => this.onopen?.());
  }

  close(): void {
    if (this.readyState === 'closed') return;
    this.readyState = 'closed';
    queueMicrotask(() => this.onclose?.());
  }
}

class FakeRTCPeerConnection {
  public readonly id = `pc${++pcSeq}`;
  public localDescription: any = null;
  public remoteDescription: any = null;
  public connectionState: RTCPeerConnectionState = 'new';
  public iceConnectionState: RTCIceConnectionState = 'new';

  public onicecandidate: ((e: { candidate: any }) => void) | null = null;
  public ondatachannel: ((e: { channel: any }) => void) | null = null;
  public onconnectionstatechange: (() => void) | null = null;

  public localChannel: FakeDataChannel | null = null;
  public remoteChannel: FakeDataChannel | null = null;

  constructor() {
    registry.set(this.id, this);
  }

  createDataChannel(label: string): FakeDataChannel {
    const ch = new FakeDataChannel(label);
    this.localChannel = ch;
    return ch;
  }

  /** 接続ごとに異なる疑似 DTLS 指紋 (実ブラウザと同じく SDP の a=fingerprint に載せる) */
  get fingerprint(): string {
    const hex = Array.from(this.id.padEnd(32, '#'))
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
      .slice(0, 32);
    return `sha-256 ${hex.join(':')}`;
  }

  async createOffer(): Promise<{ type: 'offer'; sdp: string }> {
    const sdp = `v=0\r\no=- ${this.id} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:${this.fingerprint}\r\n`;
    return { type: 'offer', sdp };
  }

  async createAnswer(): Promise<{ type: 'answer'; sdp: string }> {
    const sdp = `v=0\r\no=- ${this.id} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:${this.fingerprint}\r\n`;
    return { type: 'answer', sdp };
  }

  async setLocalDescription(desc: any): Promise<void> {
    this.localDescription = desc;
    queueMicrotask(() => {
      this.onicecandidate?.({
        candidate: { candidate: `candidate:1 1 UDP 1 127.0.0.1 9999 typ host`, sdpMid: '0', sdpMLineIndex: 0 },
      });
    });
  }

  async setRemoteDescription(desc: any): Promise<void> {
    this.remoteDescription = desc;
    const match = desc?.sdp?.match(/o=- (pc\d+)/);
    if (!match) return;
    const otherId = match[1];
    const other = registry.get(otherId);
    if (!other) return;

    if (desc.type === 'offer') {
      const remote = new FakeDataChannel('data');
      this.remoteChannel = remote;
      queueMicrotask(() => {
        this.ondatachannel?.({ channel: remote });
      });
      if (other.localChannel) {
        other.localChannel.peer = remote;
        remote.peer = other.localChannel;
      }
    } else if (desc.type === 'answer') {
      if (this.localChannel && other.remoteChannel) {
        this.localChannel.peer = other.remoteChannel;
        other.remoteChannel.peer = this.localChannel;
        this.localChannel.open();
        other.remoteChannel.open();
        this.connectionState = 'connected';
        other.connectionState = 'connected';
        this.onconnectionstatechange?.();
        other.onconnectionstatechange?.();
      }
    }
  }

  async addIceCandidate(_candidate: any): Promise<void> {}

  close(): void {
    this.connectionState = 'closed';
    this.localChannel?.close();
    this.remoteChannel?.close();
    registry.delete(this.id);
  }
}

export function installFakeWebRTC(): void {
  const g = globalThis as any;
  g.RTCPeerConnection = FakeRTCPeerConnection;
  g.RTCSessionDescription = class {
    type: string;
    sdp: string;
    constructor(init: any) {
      this.type = init?.type;
      this.sdp = init?.sdp;
    }
  };
  g.RTCIceCandidate = class {
    candidate: string;
    constructor(init: any) {
      this.candidate = init?.candidate ?? '';
    }
  };
}

export function resetFakeWebRTC(): void {
  registry.clear();
  pcSeq = 0;
}
