/**
 * `recoverTally` and `verifyTallyAgainstTotals` — the two ways to establish a tally.
 *
 * `recoverTally` *solves* the discrete log; `verifyTallyAgainstTotals` *checks* one
 * someone already published. They are equally conclusive (the discrete log is
 * unique) but not equally expensive, so these tests pin both the agreement between
 * them and the three guards the checking path relies on:
 *
 *   1. `T_j · P₂ == τ_j`   — the equality itself
 *   2. `0 ≤ T_j ≤ bound`   — closes the `T + q` aliasing gap
 *   3. `Σ_j T_j == bound`  — pins the vector as a whole, in exact mode
 *
 * The cases mirror geg's `tests/test_services_e2e.py::test_check_result_*` so a
 * divergence between the two implementations shows up as the same test failing
 * twice rather than as a silent disagreement at tally time.
 */

import {
  type Ciphertext,
  type PartialDecryption,
  G2Point,
  Transcript,
  encrypt,
  initCurves,
  partialDecrypt,
  recoverTally,
  sumCts,
  verifyTallyAgainstTotals,
} from '../src';
import { Q, modQ, randomScalar } from '../src/crypto/field';

beforeAll(async () => {
  await initCurves();
});

const T = 2;
const N = 5;
const CANDIDATES = 3;
const BUDGET = 3;

/** Every voter spends the full budget, so exact mode's sum identity holds. */
const VOTERS: bigint[][] = [
  [3n, 0n, 0n],
  [1n, 1n, 1n],
  [0n, 2n, 1n],
  [2n, 0n, 1n],
];
const UPPER_BOUND = BigInt(VOTERS.length * BUDGET); // budget × Σ weights, all weights 1
const EXPECTED: bigint[] = [6n, 3n, 3n];

function simulateDKG(t: number, n: number) {
  const coeffs = Array.from({ length: t + 1 }, () => randomScalar());
  const P2 = G2Point.generator();
  const mpk = P2.mul(coeffs[0]!);
  const msk_k: bigint[] = [];
  const mpk_k: G2Point[] = [];
  for (let k = 0; k < n; k++) {
    const a = BigInt(k + 1);
    let acc = 0n;
    let pow = 1n;
    for (let i = 0; i <= t; i++) {
      acc = modQ(acc + coeffs[i]! * pow);
      pow = modQ(pow * a);
    }
    msk_k.push(acc);
    mpk_k.push(P2.mul(acc));
  }
  return { mpk, msk_k, mpk_k };
}

const transcriptFor = (j: number) => new Transcript(`tally:${j}`);

/** A completed election: per-candidate sums plus a verified quorum of shares. */
function tallied() {
  const dkg = simulateDKG(T, N);

  const ctSums: Ciphertext[] = [];
  for (let j = 0; j < CANDIDATES; j++) {
    ctSums.push(sumCts(VOTERS.map((v) => encrypt(v[j]!, dkg.mpk).ct)));
  }

  const subset = [0, 2, 4]; // keypers 1, 3, 5 — a t+1 quorum
  const sharesPerCandidate: PartialDecryption[][] = ctSums.map((ctSum, j) =>
    subset.map((k) =>
      partialDecrypt(ctSum, dkg.msk_k[k]!, dkg.mpk_k[k]!, k + 1, transcriptFor(j)),
    ),
  );

  return {
    ctSums,
    sharesPerCandidate,
    committeePKs: dkg.mpk_k,
    threshold: T,
    transcriptFor,
  };
}

describe('recoverTally', () => {
  it('recovers the per-candidate totals by solving', () => {
    const totals = recoverTally({ ...tallied(), upperBound: UPPER_BOUND });
    expect(totals).toEqual(EXPECTED);
  });

  it('refuses a candidate short of a quorum', () => {
    const env = tallied();
    env.sharesPerCandidate[1] = env.sharesPerCandidate[1]!.slice(0, T);
    expect(() => recoverTally({ ...env, upperBound: UPPER_BOUND })).toThrow(
      /candidate 1 has 2 shares, need at least 3/,
    );
  });
});

describe('verifyTallyAgainstTotals', () => {
  it('accepts what recoverTally produced — the two paths must agree', () => {
    const env = tallied();
    const solved = recoverTally({ ...env, upperBound: UPPER_BOUND });
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: solved,
      upperBound: UPPER_BOUND,
    });
    expect(res).toEqual({ ok: true, reason: null });
  });

  it('accepts the true totals', () => {
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: EXPECTED,
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(true);
  });

  it('rejects totals above the bound before touching the group', () => {
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: [UPPER_BOUND + 1n, 0n, 0n],
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/^result:/);
    expect(res.reason).toContain('outside [0, 12]');
  });

  it('rejects T + q, which is the same group element as T', () => {
    // The reason the range check is not decoration: `(T + q)·P₂ == T·P₂`, so the
    // equality alone would accept a nonsense 256-bit integer as the tally.
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: [EXPECTED[0]! + Q, EXPECTED[1]!, EXPECTED[2]!],
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('outside');
  });

  it('rejects wrong totals that sum correctly', () => {
    // [12, 0, 0] sums to the bound exactly, like the true [6, 3, 3], so only the
    // per-candidate equality separates them.
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: [12n, 0n, 0n],
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('does not decrypt the aggregate');
  });

  it('rejects totals that do not sum to the bound in exact mode', () => {
    // [6, 3, 0] decrypts two candidates correctly and still cannot be the result:
    // every admitted ballot spends its whole budget, so the totals must sum to it.
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: [6n, 3n, 0n],
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/^result:/);
  });

  it('allows a short sum in atMost mode', () => {
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: EXPECTED,
      upperBound: UPPER_BOUND + 5n, // headroom: atMost only requires ≤
      mode: 'atMost',
    });
    expect(res.ok).toBe(true);
  });

  it('reports share failures under a distinguishable prefix', () => {
    // A committee that never produced a quorum is an availability problem; a
    // publisher with wrong totals is an integrity problem. They need different
    // responses, so the prefix has to tell them apart.
    const env = tallied();
    env.sharesPerCandidate[0] = env.sharesPerCandidate[0]!.slice(0, T);
    const res = verifyTallyAgainstTotals({
      ...env,
      claimedTotals: EXPECTED,
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/^shares:/);
  });

  it('rejects a totals vector of the wrong length', () => {
    const res = verifyTallyAgainstTotals({
      ...tallied(),
      claimedTotals: [6n, 3n],
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('2 totals published for 3 candidates');
  });

  it('rejects a share whose DLEQ was produced under a different transcript', () => {
    const env = tallied();
    const res = verifyTallyAgainstTotals({
      ...env,
      transcriptFor: (j: number) => new Transcript(`wrong:${j}`),
      claimedTotals: EXPECTED,
      upperBound: UPPER_BOUND,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/^shares:/);
    expect(res.reason).toContain('failed verification');
  });
});
