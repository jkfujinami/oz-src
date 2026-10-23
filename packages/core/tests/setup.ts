import { equixReady } from '../src/crypto/equix/EquiX';
import { sodiumReady } from '../src/crypto/sodium';

// 全テスト共通: Equi-X の Wasm と libsodium を読み込んでから始める
await equixReady;
await sodiumReady;
