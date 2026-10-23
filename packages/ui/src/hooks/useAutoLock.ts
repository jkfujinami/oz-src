import { useEffect, useRef } from 'react';

/**
 * 操作が無いまま (ウィンドウが隠れている間も含む) この時間が過ぎたら自動でロックする。
 *
 * ★ ロック解除したまま席を離れた端末は、押収された時点でメモリに鍵がある。
 *   ブラウザのタブを放置する・ウィンドウをトレイに隠すといった使い方でも、
 *   一定時間でパスワード画面に戻す。
 */
export const AUTO_LOCK_MS = 15 * 60 * 1000;

/** 期限の判定間隔。隠れたタブはタイマーが間引かれる (多くは 1 分に 1 回) ので、復帰時にも判定する */
const CHECK_INTERVAL_MS = 15 * 1000;

const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const;

export function useAutoLock(opts: {
  /** 解除済みのときだけ有効 */
  enabled: boolean;
  onLock: () => void;
  limitMs?: number;
}): void {
  const { enabled, limitMs = AUTO_LOCK_MS } = opts;
  const onLockRef = useRef(opts.onLock);
  onLockRef.current = opts.onLock;

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return;
    let lastActive = Date.now();
    let fired = false;

    const check = () => {
      if (fired) return;
      if (Date.now() - lastActive >= limitMs) {
        fired = true;
        onLockRef.current();
      }
    };
    const touch = () => { lastActive = Date.now(); };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        touch(); // 隠した時点までは操作していたとみなす
      } else {
        check(); // 隠れている間にタイマーが止められていた分を、戻った瞬間に判定する
        if (!fired) touch();
      }
    };

    // pointermove は頻度が高いので、記録は時刻の代入だけにしてある
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, touch, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    const timer = setInterval(check, Math.min(CHECK_INTERVAL_MS, limitMs));
    return () => {
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, touch);
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(timer);
    };
  }, [enabled, limitMs]);
}
