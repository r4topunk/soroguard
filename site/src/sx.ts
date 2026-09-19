import type { CSSProperties } from "react";

// Inline style strings (as produced by computeVals) -> React style objects. Memoized: the set of strings is small.
const cache = new Map<string, CSSProperties>();

const prop = (k: string): string =>
  k.startsWith("-webkit-")
    ? "Webkit" +
      k
        .slice(8)
        .replace(/-([a-z])/g, (_, c: string) => c.toUpperCase())
        .replace(/^./, (c) => c.toUpperCase())
    : k.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());

export function sx(css: string): CSSProperties {
  const hit = cache.get(css);
  if (hit) return hit;
  const out: Record<string, string> = {};
  for (const decl of css.split(";")) {
    const i = decl.indexOf(":");
    if (i < 0) continue;
    const k = decl.slice(0, i).trim();
    if (k) out[prop(k)] = decl.slice(i + 1).trim();
  }
  cache.set(css, out);
  return out;
}
