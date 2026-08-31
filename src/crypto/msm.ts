/**
 * Multi-scalar multiplication in G₂ — `Σ scalarᵢ · Pᵢ` — by the bucket method.
 *
 * Why this exists: the vendored BLST build exposes only single-point `mult`, so
 * the natural way to weight and sum a set of ciphertexts is one scalar
 * multiplication per point. In this WASM build that costs ~6 ms each, which makes
 * recomputing a 1,000-ballot aggregate ~6 s *per candidate* — enough to freeze a
 * browser tab. The bucket method replaces almost all of those multiplications with
 * additions (~20 µs), and amortises the fixed bucket-reduction cost across the
 * whole set, so it gets *better* as the input grows.
 *
 * Two properties matter beyond the speed:
 *
 *   - **The result is byte-identical to the sequential fold**, not merely equal
 *     modulo some tolerance. Point addition is associative and commutative and the
 *     compressed encoding is canonical, so any summation order yields the same 96
 *     bytes. That is what lets this stand in for the keypers' own aggregation, and
 *     it is asserted directly in the tests rather than assumed.
 *   - **Cost is logarithmic in scalar magnitude**, not linear. Window count comes
 *     from the *largest* scalar actually present, so a set of small weights stays
 *     cheap and raising the ceiling on voting power costs this step almost nothing.
 *
 * Built on `add`/`sub`/`mul` alone, so it needs no additions to the BLST surface.
 */

import { G2Point } from './curve';

/**
 * Largest window this will use, and therefore the bucket ceiling: `2^8 - 1 = 255`
 * live points, about 73 KB against the fixed 16 MB WASM heap.
 *
 * Capped explicitly rather than derived, because buckets are the only unbounded
 * allocation in here — one window of `c` bits holds `2^c - 1` of them, so letting
 * `c` grow with the input would trade a heap abort for the speed it was meant to
 * buy.
 */
const MAX_WINDOW_BITS = 8;

/** Bit length of the largest scalar, which sets how many windows are needed. */
function maxBitLength(scalars: readonly bigint[]): number {
  let max = 0n;
  for (const s of scalars) if (s > max) max = s;
  return max === 0n ? 0 : max.toString(2).length;
}

/**
 * Window size for `n` points.
 *
 * Bucket reduction costs ~`2^c` additions per window regardless of `n`, so a wide
 * window only pays off once there are enough points to amortise it. `log2(n)` is
 * the standard choice and lands close enough to optimal here; the floor of 2 keeps
 * tiny inputs from degenerating into one window per bit.
 */
function windowBits(n: number): number {
  if (n <= 1) return 1;
  return Math.max(2, Math.min(MAX_WINDOW_BITS, Math.floor(Math.log2(n))));
}

/**
 * `Σ scalarsᵢ · pointsᵢ`, as a freshly allocated point the caller owns.
 *
 * Scalars must be non-negative. Zero scalars and zero digits are skipped rather
 * than multiplied, so a sparse set costs little. The inputs are left untouched —
 * every intermediate allocated here is freed before returning, including on the
 * throwing path.
 */
export function msmG2(
  scalars: readonly bigint[],
  points: readonly G2Point[]
): G2Point {
  if (scalars.length !== points.length) {
    throw new Error(
      `msmG2: scalars.length (${scalars.length}) != points.length (${points.length})`
    );
  }
  for (let i = 0; i < scalars.length; i++) {
    if (scalars[i]! < 0n) {
      throw new Error(`msmG2: scalars[${i}] is negative (${scalars[i]})`);
    }
  }

  const bits = maxBitLength(scalars);
  // Every scalar is zero (or there are none): the sum is the identity.
  if (bits === 0) return G2Point.identity();

  const c = windowBits(points.length);
  const numWindows = Math.ceil(bits / c);
  const bucketCount = (1 << c) - 1;
  const mask = BigInt(bucketCount);
  const shiftPerWindow = 1n << BigInt(c);

  let total: G2Point | null = null;

  try {
    // Most-significant window first, shifting the running total left by one
    // window each step — Horner's rule, so the shift happens `numWindows - 1`
    // times rather than once per window.
    for (let w = numWindows - 1; w >= 0; w--) {
      if (total !== null) {
        const shifted: G2Point = total.mul(shiftPerWindow);
        total.destroyWasm();
        total = shifted;
      }

      const buckets: (G2Point | null)[] = new Array(bucketCount + 1).fill(null);
      try {
        for (let i = 0; i < points.length; i++) {
          const digit = Number((scalars[i]! >> BigInt(w * c)) & mask);
          if (digit === 0) continue;
          const existing = buckets[digit];
          if (existing === null) {
            // `add` to the identity rather than keeping a reference: the caller
            // owns `points[i]`, and freeing it here would be a use-after-free for
            // them. This copy is ours to free.
            const zero = G2Point.identity();
            buckets[digit] = zero.add(points[i]!);
            zero.destroyWasm();
          } else {
            const next = existing.add(points[i]!);
            existing.destroyWasm();
            buckets[digit] = next;
          }
        }

        // Σ_d d · bucket[d] in 2·bucketCount additions instead of a
        // multiplication per bucket: walking down and carrying a running sum
        // makes bucket d contribute exactly d times.
        let running: G2Point | null = null;
        let windowSum: G2Point | null = null;
        try {
          for (let d = bucketCount; d >= 1; d--) {
            const bucket = buckets[d];
            if (bucket !== null) {
              const nextRunning: G2Point =
                running === null
                  ? bucket.add(G2Point.identity())
                  : running.add(bucket);
              if (running !== null) running.destroyWasm();
              running = nextRunning;
            }
            if (running !== null) {
              const nextSum: G2Point =
                windowSum === null
                  ? running.add(G2Point.identity())
                  : windowSum.add(running);
              if (windowSum !== null) windowSum.destroyWasm();
              windowSum = nextSum;
            }
          }

          if (windowSum !== null) {
            if (total === null) {
              total = windowSum;
              windowSum = null; // ownership moved into `total`
            } else {
              const next: G2Point = total.add(windowSum);
              total.destroyWasm();
              total = next;
            }
          }
        } finally {
          if (running !== null) running.destroyWasm();
          if (windowSum !== null) windowSum.destroyWasm();
        }
      } finally {
        for (const b of buckets) if (b !== null) b.destroyWasm();
      }
    }
  } catch (err) {
    if (total !== null) total.destroyWasm();
    throw err;
  }

  return total ?? G2Point.identity();
}
