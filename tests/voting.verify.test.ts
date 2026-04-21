import { keccak256 } from 'viem';
import {
  BallotInputs,
  BallotValidityProof,
  BallotVerifyParams,
  G2Point,
  canonicalBallotMessage,
  encodeBallotValidityProof,
  encodeSchnorr,
  encrypt,
  initCurves,
  proveBudgetAtMost,
  proveBudgetExact,
  proveOR,
  randomScalar,
  rangeCandidates,
  schnorrKeygen,
  schnorrSign,
  seedBallotTranscript,
  sumCts,
  verifyBallot,
} from '../src';

beforeAll(async () => {
  await initCurves();
});

function trustedSetup() {
  const msk = randomScalar();
  const mpk = G2Point.generator().mul(msk);
  return { msk, mpk };
}

/**
 * Frontend-side ballot assembly. Lives in tests, not in src, to honour
 * the "no ballot builder" decision — consumers wire these calls up
 * themselves using the primitives the SDK exposes.
 */
function buildBallot(args: {
  mpk: G2Point;
  electionId: Uint8Array;
  pseudonym: Uint8Array;
  votes: bigint[];
  params: BallotVerifyParams;
  wrAttestation?: Uint8Array;
}): { inputs: BallotInputs; sk: bigint } {
  const { mpk, electionId, pseudonym, votes, params } = args;
  if (votes.length !== params.numCandidates) {
    throw new Error('buildBallot: votes.length mismatch');
  }
  if (params.variant !== 'A') throw new Error('buildBallot: only Variant A');

  const { sk, vk } = schnorrKeygen();

  const perCand = votes.map((v) => encrypt(v, mpk));
  const cts = perCand.map((p) => p.ct);
  const rs = perCand.map((p) => p.r);

  const t = seedBallotTranscript(electionId, mpk, vk, cts, params);

  const candidates = rangeCandidates(params.budget);
  const rangeOrBit = cts.map((ct, j) => {
    t.append('ballot:range', u16BE(j));
    return proveOR(
      { ct, mpk, candidates },
      { r: rs[j]!, trueIndex: Number(votes[j]!) },
      t,
    );
  });

  const ctSum = sumCts(cts);
  const rSum = rs.reduce((a, r) => a + r, 0n);
  const V = votes.reduce((a, b) => a + b, 0n);
  t.append('ballot:budget', new Uint8Array([0]));
  const budget =
    params.mode === 'exact'
      ? proveBudgetExact({ ctSum, mpk, budget: BigInt(params.budget) }, { rSum }, t)
      : proveBudgetAtMost(
          { ctSum, mpk, budget: BigInt(params.budget) },
          { rSum, V },
          t,
        );

  const bvp: BallotValidityProof = {
    version: 0x01,
    variant: 'A',
    rangeOrBit,
    budget,
  };
  const zkProof = encodeBallotValidityProof(bvp);

  const ciphertextBytes: [Uint8Array, Uint8Array][] = cts.map((ct) => [
    ct.c1.toBytes(),
    ct.c2.toBytes(),
  ]);

  const preimage = canonicalBallotMessage({
    electionId,
    pseudonym,
    ciphertexts: ciphertextBytes,
    zkProof,
  });
  const msg = keccak256(preimage, 'bytes');
  const sig = schnorrSign(sk, vk, msg);

  return {
    inputs: {
      electionId,
      pseudonym,
      vk: vk.toBytes(),
      ciphertexts: ciphertextBytes,
      zkProof,
      voterSignature: encodeSchnorr(sig),
      wrAttestation: args.wrAttestation ?? new Uint8Array([0x01]),
    },
    sk,
  };
}

function u16BE(n: number): Uint8Array {
  const o = new Uint8Array(2);
  o[0] = (n >>> 8) & 0xff;
  o[1] = n & 0xff;
  return o;
}

const accept = () => true;
const reject = () => false;

describe('canonicalBallotMessage', () => {
  it('is deterministic for identical inputs', () => {
    const args = {
      electionId: new Uint8Array(32).fill(0x11),
      pseudonym: new Uint8Array(32).fill(0x22),
      ciphertexts: [
        [new Uint8Array(96).fill(0xaa), new Uint8Array(96).fill(0xbb)] as [
          Uint8Array,
          Uint8Array,
        ],
      ],
      zkProof: new Uint8Array([1, 2, 3]),
    };
    const a = canonicalBallotMessage(args);
    const b = canonicalBallotMessage(args);
    expect(a).toEqual(b);
  });

  it('flipping any field changes the preimage', () => {
    const base = {
      electionId: new Uint8Array(32).fill(0x11),
      pseudonym: new Uint8Array(32).fill(0x22),
      ciphertexts: [
        [new Uint8Array(96).fill(0xaa), new Uint8Array(96).fill(0xbb)] as [
          Uint8Array,
          Uint8Array,
        ],
      ],
      zkProof: new Uint8Array([1, 2, 3]),
    };
    const variants = [
      { ...base, electionId: new Uint8Array(32).fill(0x12) },
      { ...base, pseudonym: new Uint8Array(32).fill(0x23) },
      { ...base, zkProof: new Uint8Array([1, 2, 4]) },
      {
        ...base,
        ciphertexts: [
          [new Uint8Array(96).fill(0xac), new Uint8Array(96).fill(0xbb)] as [
            Uint8Array,
            Uint8Array,
          ],
        ],
      },
    ];
    const baseBytes = canonicalBallotMessage(base);
    for (const v of variants) {
      expect(canonicalBallotMessage(v)).not.toEqual(baseBytes);
    }
  });

  it('rejects ciphertext components of the wrong length', () => {
    expect(() =>
      canonicalBallotMessage({
        electionId: new Uint8Array(32),
        pseudonym: new Uint8Array(32),
        ciphertexts: [[new Uint8Array(95), new Uint8Array(96)]],
        zkProof: new Uint8Array(0),
      }),
    ).toThrow(/96 bytes/);
  });
});

describe('verifyBallot — Variant A, exact budget', () => {
  const params: BallotVerifyParams = {
    numCandidates: 3,
    budget: 2,
    mode: 'exact',
    variant: 'A',
  };

  it('honest ballot verifies', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32).fill(0xde),
      pseudonym: new Uint8Array(32).fill(0xad),
      votes: [1n, 1n, 0n], // V = 2 = B
      params,
    });
    expect(verifyBallot(inputs, params, mpk, accept)).toEqual({ ok: true });
  });

  it('rejects when wrAttestation verifier rejects', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 0n],
      params,
    });
    const r = verifyBallot(inputs, params, mpk, reject);
    expect(r).toEqual({ ok: false, reason: 'wrAttestation verification failed' });
  });

  it('rejects a flipped byte in a ciphertext', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [2n, 0n, 0n],
      params,
    });
    // Corrupt the first ciphertext's C1 point bytes.
    const tampered = inputs.ciphertexts.map(([c1, c2], i) => {
      if (i !== 0) return [c1, c2] as [Uint8Array, Uint8Array];
      const bad = new Uint8Array(c1);
      bad[50] ^= 0x01;
      return [bad, c2] as [Uint8Array, Uint8Array];
    });
    const r = verifyBallot(
      { ...inputs, ciphertexts: tampered },
      params,
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
  });

  it('rejects ballot copied under a different vk (voter impersonation)', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 0n],
      params,
    });
    const { vk: vk2 } = schnorrKeygen();
    const r = verifyBallot({ ...inputs, vk: vk2.toBytes() }, params, mpk, accept);
    expect(r.ok).toBe(false);
  });

  it('rejects a wrong electionId (cross-election replay)', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32).fill(0x01),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 0n],
      params,
    });
    const r = verifyBallot(
      { ...inputs, electionId: new Uint8Array(32).fill(0x02) },
      params,
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
  });

  it('rejects when declared budget differs from signed budget', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 0n], // V = 2 = B
      params,
    });
    // Verifier is told B = 3 — decoder size mismatch.
    const r = verifyBallot(
      inputs,
      { ...params, budget: 3 },
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
  });

  it('rejects ciphertexts.length not matching numCandidates', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 0n],
      params,
    });
    const r = verifyBallot(
      inputs,
      { ...params, numCandidates: 4 },
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/ciphertexts.length/);
  });
});

describe('verifyBallot — Variant A, at-most budget', () => {
  const params: BallotVerifyParams = {
    numCandidates: 3,
    budget: 3,
    mode: 'atMost',
    variant: 'A',
  };

  it('honest ballot verifies across V ∈ {0..B}', () => {
    const { mpk } = trustedSetup();
    const scenarios: bigint[][] = [
      [0n, 0n, 0n], // V = 0
      [1n, 0n, 0n],
      [1n, 1n, 0n],
      [2n, 1n, 0n], // V = B
    ];
    for (const votes of scenarios) {
      const { inputs } = buildBallot({
        mpk,
        electionId: new Uint8Array(32),
        pseudonym: new Uint8Array(32),
        votes,
        params,
      });
      expect(verifyBallot(inputs, params, mpk, accept)).toEqual({ ok: true });
    }
  });

  it('rejects a wire with mode=exact against params.mode=atMost', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [1n, 1n, 1n], // V = B
      params: { ...params, mode: 'exact' },
    });
    const r = verifyBallot(inputs, params, mpk, accept); // ask for atMost
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/budget mode/);
  });
});

describe('verifyBallot — structural rejections', () => {
  it('rejects an invalid vk encoding', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [0n, 0n, 0n],
      params: { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'A' },
    });
    const r = verifyBallot(
      { ...inputs, vk: new Uint8Array(48) }, // all-zero is not a valid compressed G1 point
      { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'A' },
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/vk decode/);
  });

  it('rejects Variant B explicitly (deferred to P4c)', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [0n, 0n, 0n],
      params: { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'A' },
    });
    const r = verifyBallot(
      inputs,
      { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'B', d: 1 },
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/Variant B/);
  });

  it('rejects signature forged by a different sk', () => {
    const { mpk } = trustedSetup();
    const { inputs } = buildBallot({
      mpk,
      electionId: new Uint8Array(32),
      pseudonym: new Uint8Array(32),
      votes: [0n, 0n, 0n],
      params: { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'A' },
    });
    // Resign with an unrelated key — vk in inputs stays the same, so Schnorr fails.
    const other = schnorrKeygen();
    const preimage = canonicalBallotMessage({
      electionId: inputs.electionId,
      pseudonym: inputs.pseudonym,
      ciphertexts: inputs.ciphertexts,
      zkProof: inputs.zkProof,
    });
    const forged = schnorrSign(other.sk, other.vk, keccak256(preimage, 'bytes'));
    const r = verifyBallot(
      { ...inputs, voterSignature: encodeSchnorr(forged) },
      { numCandidates: 3, budget: 1, mode: 'atMost', variant: 'A' },
      mpk,
      accept,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/signature/);
  });
});
