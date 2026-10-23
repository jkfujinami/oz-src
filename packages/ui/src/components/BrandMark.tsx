import { useId } from 'react';

/**
 * ロゴ (リポジトリ直下の icon.svg と同じ図形)。画面に複数置いてもくり抜きのマスクが混ざらないよう、id は描くたびに分ける。
 */
export function BrandMark({ size = 28 }: { size?: number }) {
  const maskId = `oz-mark-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;
  return (
    <svg className="brand-mark" viewBox="0 0 640 640" width={size} height={size} aria-hidden="true" focusable="false">
      <defs>
        <mask id={maskId}>
          <rect width="100%" height="100%" fill="#ffffff" />
          <circle cx="320" cy="198" r="108" fill="#000000" />
          <polyline
            points="266,380 380,380 245,560 404,560"
            fill="none"
            stroke="#000000"
            strokeWidth="14.5"
            strokeLinecap="butt"
            strokeLinejoin="miter"
            strokeMiterlimit="10"
          />
        </mask>
      </defs>
      <g fill="#ba327b" mask={`url(#${maskId})`}>
        <circle cx="320" cy="198" r="162" />
        <polygon points="229,329 411,329 460,617 180,617" />
      </g>
    </svg>
  );
}
