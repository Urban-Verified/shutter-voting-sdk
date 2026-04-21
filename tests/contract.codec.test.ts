import {
  BallotValidityProof,
  DLEQProof,
  G1Point,
  G2Point,
  ORProof,
  Transcript,
  decodeBallotValidityProof,
  decodeDLEQ,
  decodeSchnorr,
  encodeBallotValidityProof,
  encodeDLEQ,
  encodeSchnorr,
  encrypt,
  initCurves,
  proveBudgetAtMost,
  proveBudgetExact,
  proveOR,
  randomScalar,
  schnorrKeygen,
  schnorrSign,
  sumCts,
} from '../src';

beforeAll(async () => {
  await initCurves();
});

function trustedSetup() {
  const msk = randomScalar();
  const mpk = G2Point.generator().mul(msk);
  return { msk, mpk };
}

function freshORProof(mpk: G2Point, budget: number, trueIndex: number): ORProof {
  const candidates: bigint[] = [];
  for (let i = 0; i <= budget; i++) candidates.push(BigInt(i));
  const { ct, r } = encrypt(BigInt(trueIndex), mpk);
  return proveOR({ ct, mpk, candidates }, { r, trueIndex }, new Transcript('C'));
}

describe('encodeDLEQ / decodeDLEQ', () => {
  it('round-trips an honest DLEQ proof', () => {
    const p: DLEQProof = { e: 7n, z: 11n };
    const decoded = decodeDLEQ(encodeDLEQ(p));
    expect(decoded.e).toBe(7n);
    expect(decoded.z).toBe(11n);
  });

  it('rejects a buffer of the wrong length', () => {
    expect(() => decodeDLEQ(new Uint8Array(63))).toThrow(/expected 64/);
    expect(() => decodeDLEQ(new Uint8Array(65))).toThrow(/expected 64/);
  });
});

describe('encodeSchnorr / decodeSchnorr', () => {
  it('round-trips a real Schnorr signature', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const sig = schnorrSign(sk, vk, msg);
    const decoded = decodeSchnorr(encodeSchnorr(sig));
    expect(decoded.R.equals(sig.R)).toBe(true);
    expect(decoded.s).toBe(sig.s);
  });

  it('rejects the wrong length', () => {
    expect(() => decodeSchnorr(new Uint8Array(79))).toThrow(/expected 80/);
  });
});

describe('encodeBallotValidityProof / decodeBallotValidityProof — Variant A', () => {
  it('round-trips an exact-budget ballot proof', () => {
    const { mpk } = trustedSetup();
    const ℓ = 3;
    const B = 2;
    const rangeOrBit = [
      freshORProof(mpk, B, 1),
      freshORProof(mpk, B, 2),
      freshORProof(mpk, B, 0),
    ];
    // Exact budget: V = B. Build a sum ciphertext with V = 3 = 1+2+0.
    const votes = [1n, 2n, 0n];
    const perCand = votes.map((v) => encrypt(v, mpk));
    const ctSum = sumCts(perCand.map((p) => p.ct));
    const rSum = perCand.reduce((a, p) => a + p.r, 0n);
    const budget = proveBudgetExact(
      { ctSum, mpk, budget: BigInt(B + 1) }, // V = 3 = B+1 here, so set budget = 3
      { rSum },
      new Transcript('C'),
    );
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit,
      budget,
    };
    const bytes = encodeBallotValidityProof(bvp);
    const decoded = decodeBallotValidityProof(bytes, {
      variant: 'A',
      numCandidates: ℓ,
      budget: B,
    });
    expect(decoded.version).toBe(0x01);
    expect(decoded.variant).toBe('A');
    expect(decoded.rangeOrBit.length).toBe(ℓ);
    for (let j = 0; j < ℓ; j++) {
      expect(decoded.rangeOrBit[j]!.branches.length).toBe(B + 1);
      for (let i = 0; i <= B; i++) {
        const a = decoded.rangeOrBit[j]!.branches[i]!;
        const b = rangeOrBit[j]!.branches[i]!;
        expect(a.a1.equals(b.a1)).toBe(true);
        expect(a.a2.equals(b.a2)).toBe(true);
        expect(a.e).toBe(b.e);
        expect(a.z).toBe(b.z);
      }
    }
    expect(decoded.budget.mode).toBe('exact');
    if (decoded.budget.mode === 'exact' && budget.mode === 'exact') {
      expect(decoded.budget.proof.e).toBe(budget.proof.e);
      expect(decoded.budget.proof.z).toBe(budget.proof.z);
    }
  });

  it('round-trips an at-most-budget ballot proof', () => {
    const { mpk } = trustedSetup();
    const ℓ = 2;
    const B = 3;
    const rangeOrBit = [freshORProof(mpk, B, 2), freshORProof(mpk, B, 1)];
    const votes = [2n, 1n];
    const perCand = votes.map((v) => encrypt(v, mpk));
    const ctSum = sumCts(perCand.map((p) => p.ct));
    const rSum = perCand.reduce((a, p) => a + p.r, 0n);
    const V = 3n;
    const budget = proveBudgetAtMost(
      { ctSum, mpk, budget: BigInt(B) },
      { rSum, V },
      new Transcript('C'),
    );
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit,
      budget,
    };
    const bytes = encodeBallotValidityProof(bvp);
    const decoded = decodeBallotValidityProof(bytes, {
      variant: 'A',
      numCandidates: ℓ,
      budget: B,
    });
    expect(decoded.budget.mode).toBe('atMost');
    if (decoded.budget.mode === 'atMost' && budget.mode === 'atMost') {
      expect(decoded.budget.proof.branches.length).toBe(B + 1);
      for (let i = 0; i <= B; i++) {
        expect(decoded.budget.proof.branches[i]!.e).toBe(budget.proof.branches[i]!.e);
        expect(decoded.budget.proof.branches[i]!.z).toBe(budget.proof.branches[i]!.z);
      }
    }
  });

  it('rejects a truncated buffer', () => {
    const { mpk } = trustedSetup();
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit: [freshORProof(mpk, 1, 0)],
      budget: { mode: 'exact', proof: { e: 1n, z: 2n } },
    };
    const bytes = encodeBallotValidityProof(bvp);
    expect(() =>
      decodeBallotValidityProof(bytes.subarray(0, bytes.length - 1), {
        variant: 'A',
        numCandidates: 1,
        budget: 1,
      }),
    ).toThrow();
  });

  it('rejects a buffer with trailing bytes', () => {
    const { mpk } = trustedSetup();
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit: [freshORProof(mpk, 1, 1)],
      budget: { mode: 'exact', proof: { e: 1n, z: 2n } },
    };
    const bytes = encodeBallotValidityProof(bvp);
    const padded = new Uint8Array(bytes.length + 3);
    padded.set(bytes);
    expect(() =>
      decodeBallotValidityProof(padded, {
        variant: 'A',
        numCandidates: 1,
        budget: 1,
      }),
    ).toThrow(/trailing bytes/);
  });

  it('rejects the wrong version byte', () => {
    const buf = new Uint8Array(10);
    buf[0] = 0x02; // not 0x01
    expect(() =>
      decodeBallotValidityProof(buf, { variant: 'A', numCandidates: 1, budget: 1 }),
    ).toThrow(/unsupported version/);
  });

  it('rejects a variant mismatch between wire and params', () => {
    const { mpk } = trustedSetup();
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit: [freshORProof(mpk, 1, 0)],
      budget: { mode: 'exact', proof: { e: 1n, z: 2n } },
    };
    const bytes = encodeBallotValidityProof(bvp);
    expect(() =>
      decodeBallotValidityProof(bytes, {
        variant: 'B',
        numCandidates: 1,
        budget: 1,
        d: 1,
      }),
    ).toThrow(/Variant B not implemented/);
  });

  it('rejects n_outer mismatch', () => {
    const { mpk } = trustedSetup();
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'A',
      rangeOrBit: [freshORProof(mpk, 1, 0)], // ℓ = 1 on wire
      budget: { mode: 'exact', proof: { e: 1n, z: 2n } },
    };
    const bytes = encodeBallotValidityProof(bvp);
    expect(() =>
      decodeBallotValidityProof(bytes, {
        variant: 'A',
        numCandidates: 2, // lie
        budget: 1,
      }),
    ).toThrow(/n_outer/);
  });

  it('Variant B encode/decode throws (deferred)', () => {
    const { mpk } = trustedSetup();
    const bvp: BallotValidityProof = {
      version: 0x01,
      variant: 'B',
      rangeOrBit: [],
      budget: { mode: 'exact', proof: { e: 1n, z: 2n } },
    };
    expect(() => encodeBallotValidityProof(bvp)).toThrow(/Variant B/);
    expect(() =>
      decodeBallotValidityProof(new Uint8Array(4), {
        variant: 'B',
        numCandidates: 1,
        budget: 1,
        d: 1,
      }),
    ).toThrow(/Variant B/);
  });
});

describe('codec sanity: G1/G2 round-trips via point.toBytes()', () => {
  it('G1 and G2 identity / generator round-trip bytes', () => {
    const g1 = G1Point.generator();
    const g2 = G2Point.generator();
    expect(G1Point.fromBytes(g1.toBytes()).equals(g1)).toBe(true);
    expect(G2Point.fromBytes(g2.toBytes()).equals(g2)).toBe(true);
  });
});
