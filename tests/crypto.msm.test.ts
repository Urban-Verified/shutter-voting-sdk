/**
 * `msmG2` / `msmCt` — the bucket-method multi-scalar multiplication.
 *
 * The whole value of this primitive rests on one claim: it produces **the same 96
 * bytes** as weighting each point and adding them in order. It stands in for the
 * committee's own aggregation, so "close enough" is not a category that exists
 * here — a single differing bit reports an honest committee as having published a
 * false aggregate.
 *
 * These tests therefore compare compressed encodings rather than group equality,
 * and cover the shapes that break naive bucket implementations: zero scalars, zero
 * digits in some windows, repeated points, a single point, weights far larger than
 * any window, and scalar magnitudes spanning the range real voting power reaches.
 */

import { G2Point, addCt, encrypt, msmCt, msmG2, scalarMulCt, initCurves } from '../src';
import type { Ciphertext } from '../src';
import { randomScalar } from '../src/crypto/field';

beforeAll(async () => {
  await initCurves();
});

const hex = (p: G2Point) => Buffer.from(p.toBytes()).toString('hex');

/** The definition `msmG2` has to match: weight each point, add them in order. */
function sequential(scalars: bigint[], points: G2Point[]): G2Point {
  let acc: G2Point | null = null;
  for (let i = 0; i < points.length; i++) {
    if (scalars[i] === 0n) continue;
    const weighted = scalars[i] === 1n ? points[i]!.add(G2Point.identity()) : points[i]!.mul(scalars[i]!);
    if (acc === null) {
      acc = weighted;
    } else {
      const next: G2Point = acc.add(weighted);
      acc.destroyWasm();
      weighted.destroyWasm();
      acc = next;
    }
  }
  return acc ?? G2Point.identity();
}

function distinctPoints(n: number): G2Point[] {
  const P2 = G2Point.generator();
  const out = Array.from({ length: n }, (_, i) => P2.mul(BigInt(1000 + i * 7919)));
  P2.destroyWasm();
  return out;
}

function expectAgrees(scalars: bigint[], points: G2Point[]) {
  const viaMsm = msmG2(scalars, points);
  const viaLoop = sequential(scalars, points);
  expect(hex(viaMsm)).toBe(hex(viaLoop));
  viaMsm.destroyWasm();
  viaLoop.destroyWasm();
}

describe('msmG2 agrees byte-for-byte with the sequential fold', () => {
  it('over a spread of sizes and scalar magnitudes', () => {
    for (const n of [1, 2, 7, 33, 128]) {
      for (const bits of [1, 8, 20, 50]) {
        const points = distinctPoints(n);
        const limit = 1n << BigInt(bits);
        const scalars = Array.from(
          { length: n },
          (_, i) => (BigInt(i * 2654435761 + 1) % limit) + 1n
        );
        expectAgrees(scalars, points);
        for (const p of points) p.destroyWasm();
      }
    }
  }, 120_000);

  it('when some scalars are zero — those points must not contribute', () => {
    const points = distinctPoints(16);
    const scalars = points.map((_, i) => (i % 3 === 0 ? 0n : BigInt(i + 1)));
    expectAgrees(scalars, points);
    for (const p of points) p.destroyWasm();
  }, 60_000);

  it('when every scalar is zero — the sum is the identity', () => {
    const points = distinctPoints(5);
    const out = msmG2([0n, 0n, 0n, 0n, 0n], points);
    expect(out.isIdentity()).toBe(true);
    out.destroyWasm();
    for (const p of points) p.destroyWasm();
  });

  it('on an empty input', () => {
    const out = msmG2([], []);
    expect(out.isIdentity()).toBe(true);
    out.destroyWasm();
  });

  it('when the same point repeats — buckets must accumulate, not overwrite', () => {
    const P2 = G2Point.generator();
    const points = [P2, P2, P2].map(p => p.add(G2Point.identity()));
    P2.destroyWasm();
    expectAgrees([3n, 5n, 7n], points);
    for (const p of points) p.destroyWasm();
  }, 30_000);

  it('when a whole window is zero for every scalar', () => {
    // 2^40 + small: the middle windows are all-zero, which must be skipped
    // without disturbing the Horner shift between the populated ones.
    const points = distinctPoints(8);
    const scalars = points.map((_, i) => (1n << 40n) + BigInt(i + 1));
    expectAgrees(scalars, points);
    for (const p of points) p.destroyWasm();
  }, 60_000);

  it('on randomised inputs', () => {
    for (let trial = 0; trial < 3; trial++) {
      const n = 1 + Math.floor(Math.random() * 40);
      const points = distinctPoints(n);
      const scalars = Array.from({ length: n }, () => randomScalar() % (1n << 50n));
      expectAgrees(scalars, points);
      for (const p of points) p.destroyWasm();
    }
  }, 120_000);

  it('rejects a length mismatch and negative scalars', () => {
    const points = distinctPoints(2);
    expect(() => msmG2([1n], points)).toThrow(/scalars.length/);
    expect(() => msmG2([1n, -1n], points)).toThrow(/negative/);
    for (const p of points) p.destroyWasm();
  });
});

describe('msmCt', () => {
  it('matches weighting and adding ciphertexts in order', () => {
    const P2 = G2Point.generator();
    const mpk = P2.mul(987654321987654321n);
    P2.destroyWasm();

    const cts: Ciphertext[] = [3n, 0n, 1n, 2n].map(v => encrypt(v, mpk).ct);
    const weights = [5n, 12n, 1n, 999n];

    const viaMsm = msmCt(weights, cts);

    let acc: Ciphertext | null = null;
    for (let i = 0; i < cts.length; i++) {
      const w = scalarMulCt(weights[i]!, cts[i]!);
      acc = acc === null ? w : addCt(acc, w);
    }

    expect(hex(viaMsm.c1)).toBe(hex(acc!.c1));
    expect(hex(viaMsm.c2)).toBe(hex(acc!.c2));
  }, 60_000);
});
