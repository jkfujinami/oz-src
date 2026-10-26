/**
 * RingSelect: JOIN 時に返すピアの選び方 (純関数。Node / Edge 両方から使う)。
 *
 * - リング近傍: 時計回り最近接 2 + 反時計回り最近接 2
 *   (u が v の時計回り最近接 2 に入るなら v は u の反時計回り最近接 2 に入る。
 *    PeerManager は方向付き近傍を Eviction から保護するので相手側でも残る)
 * - 新着 2: 参加が新しいノードほど次数に空きがある
 * - 残りはランダム: 長距離リンクと、早期参加者の独占防止
 *
 * k < MIN_STRUCTURED のときは従来どおり純ランダム。
 */

export interface RingCandidate<T> {
  item: T;
  /** [0, 1) のリング座標 */
  position: number;
  /** 参加時刻 (ms) */
  joinedAt: number;
}

export const RING_SELECT = {
  MIN_STRUCTURED: 6,
  NEIGHBORS_PER_SIDE: 2,
  RECENT: 2,
} as const;

function cwDist(from: number, to: number): number {
  const d = to - from;
  return d < 0 ? d + 1 : d;
}

function shuffle<T>(arr: T[], randomInt: (n: number) => number): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const tmp = arr[i]!;
    arr[i] = arr[j]!;
    arr[j] = tmp;
  }
}

export function selectJoinPeers<T>(
  selfPosition: number | null,
  candidates: RingCandidate<T>[],
  k: number,
  randomInt: (n: number) => number,
): T[] {
  const pool = candidates.slice();
  if (selfPosition === null || k < RING_SELECT.MIN_STRUCTURED || pool.length <= k) {
    shuffle(pool, randomInt);
    return pool.slice(0, k).map((c) => c.item);
  }

  const picked: RingCandidate<T>[] = [];
  const used = new Set<RingCandidate<T>>();
  const take = (list: RingCandidate<T>[], n: number): void => {
    let got = 0;
    for (const c of list) {
      if (got >= n || picked.length >= k) return;
      if (used.has(c)) continue;
      used.add(c);
      picked.push(c);
      got++;
    }
  };

  const self = selfPosition;
  take(pool.slice().sort((a, b) => cwDist(self, a.position) - cwDist(self, b.position)), RING_SELECT.NEIGHBORS_PER_SIDE);
  take(pool.slice().sort((a, b) => cwDist(a.position, self) - cwDist(b.position, self)), RING_SELECT.NEIGHBORS_PER_SIDE);
  take(pool.slice().sort((a, b) => b.joinedAt - a.joinedAt), RING_SELECT.RECENT);

  const rest = pool.filter((c) => !used.has(c));
  shuffle(rest, randomInt);
  take(rest, k - picked.length);

  return picked.map((c) => c.item);
}
