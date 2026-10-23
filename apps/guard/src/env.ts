// ★ このファイルは OzNode を作る前に 1 度だけ呼ぶ。core は WebRTC / WebSocket / IndexedDB を
//   グローバル (ブラウザの API) から引くので、Node ではここで同じ名前のものを生やす。
//   WebRTCPeer / SignalingClient / IndexedDBStore は使う時点でグローバルを読むため、import の順序は問わない。
import 'fake-indexeddb/auto';
import { IDBFactory as FakeIDBFactory } from 'fake-indexeddb';
import WebSocket from 'ws';

/** 新しい (空の) IndexedDB の実体 */
export function createIndexedDbFactory(): IDBFactory {
  return new FakeIDBFactory() as unknown as IDBFactory;
}

/**
 * Node にブラウザ相当のグローバルを用意する。
 *
 * - RTCPeerConnection 等: node-datachannel/polyfill (libdatachannel)。
 * - WebSocket: ws。Node 22 には組み込みがあるが、20 には無い。版による差を無くすため常に ws を使う。
 * - indexedDB: 渡された fake-indexeddb の実体 (スナップショットから復元済みのもの)。
 */
export async function installNodeGlobals(indexedDb: IDBFactory): Promise<void> {
  const g = globalThis as Record<string, unknown>;
  const rtc = await import('node-datachannel/polyfill');
  g.RTCPeerConnection = rtc.RTCPeerConnection;
  g.RTCSessionDescription = rtc.RTCSessionDescription;
  g.RTCIceCandidate = rtc.RTCIceCandidate;
  g.RTCDataChannel = rtc.RTCDataChannel;
  g.WebSocket = WebSocket;
  g.indexedDB = indexedDb;
}
