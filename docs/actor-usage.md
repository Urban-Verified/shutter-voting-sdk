# Actor Usage Guide

This document maps every actor in the Munich *Personalratswahl* voting flow to
the **exact SDK functions** they must call and the **exact arguments** they
must supply. It is a reading of `src/index.ts`: only symbols exported from the
SDK are named here.

The four actors covered:

1. **Election Authority** — publishes election parameters; does not call the
   SDK at runtime but fixes the values everybody else passes in.
2. **Voter (frontend / client)** — encrypts votes, builds the ballot validity
   proof, signs the canonical preimage.
3. **Vote Registry / Vote Proxy / auditor (ballot verifier)** — verifies each
   submitted ballot before it is admitted to the tally.
4. **Keyper (committee member)** — after the vote phase closes, computes a
   partial decryption share on the homomorphic ciphertext sum.
5. **Tally Aggregator** — verifies keyper shares, combines a threshold set,
   runs BSGS to recover each candidate's integer tally.

> Every caller **must** call `await initCurves()` exactly once before
> invoking anything else. The BLST WASM heap is a singleton and is not
> re-entrant across workers — do not call decryption benchmarks and ballot
> benchmarks in the same worker.

---

## Shared setup

```ts
import { initCurves } from '@shutter-network/shutter-voting-sdk';
await initCurves();
```

## Shared parameter bag — `BallotVerifyParams`

The voter, the ballot verifier, and anything that reconstructs the budget
proof all need the **identical** parameter bag:

```ts
type BallotVerifyParams = {
  numCandidates: number;       // ℓ, 1..65535
  budget:        number;       // B, 1..65535
  mode:         'exact' | 'atMost';
  variant:      'A' | 'B';
  d?:            number;       // Variant B only: must equal ⌈log₂(B+1)⌉
};
```

Drift in **any** field between prover and verifier makes every ballot fail —
the values are bound into the Fiat–Shamir transcript (`seedBallotTranscript`)
and into the wire codec.

---

## 1. Election Authority

The Election Authority does not run SDK code at ballot time; it publishes
on-chain constants that every other actor reads. Those constants are:

| Constant           | Used by                                              | Notes                                                                 |
| ------------------ | ---------------------------------------------------- | --------------------------------------------------------------------- |
| `electionId` (32B) | voter, verifier, keyper transcript                   | Bound into `canonicalBallotMessage` and `seedBallotTranscript`.       |
| `mpk: G2Point`     | voter (to encrypt), verifier, keyper                 | Committee public key from DKG. Must **not** be the identity.          |
| `numCandidates ℓ`  | voter, verifier                                      | Number of candidates on the ballot.                                   |
| `budget B`         | voter, verifier, tally (BSGS upper bound = `ℓ · B`) | Max votes per ballot.                                                 |
| `mode`             | voter, verifier                                      | `'exact'` forces V = B; `'atMost'` allows V ≤ B.                      |
| `variant`          | voter, verifier                                      | `'A'` = direct range proofs; `'B'` = bit-decomposition.               |
| `d` (Variant B)    | voter, verifier                                      | **Must** be `Math.ceil(Math.log2(B + 1))`.                            |
| Keyper committee   | tally aggregator, auditors                           | Each keyper k holds `msk_k`; its `mpk_k = msk_k · P₂` is on chain.   |
| Threshold `t`      | tally aggregator                                     | Need any `t + 1` verified shares to reconstruct.                      |

The Election Authority itself calls **no SDK functions**.

---

## 2. Voter (frontend / client)

The voter's job is to produce a `BallotInputs` struct and submit it to the
Vote Registry. Concrete call sequence:

### 2.1 Key material

```ts
import { schnorrKeygen } from '@shutter-network/shutter-voting-sdk';

// Fresh ephemeral Schnorr keypair, bound to this ballot only.
const { sk, vk } = schnorrKeygen();           // sk: bigint, vk: G1Point
```

The voter registers `vk.toBytes()` with the Wahlregister-Server to obtain the
WR attestation (`wrAttestation: Uint8Array`) and a `pseudonym: Uint8Array` (32
bytes). **Both are opaque to the SDK** — the SDK only passes them through to
the caller-supplied attestation verifier.

### 2.2 Encrypt votes

Let `votes: bigint[]` be the length-`ℓ` vector of per-candidate votes. Each
`votes[j] ∈ [0, B]` and, when `mode === 'exact'`, `Σ votes[j] === B`.

**Variant A** — one ciphertext per candidate:

```ts
import { encrypt } from '@shutter-network/shutter-voting-sdk';

const perCand = votes.map((v) => encrypt(v, mpk));  // { ct, r }[]
const cts = perCand.map(p => p.ct);                 // Ciphertext[ℓ]
const rs  = perCand.map(p => p.r);                  // bigint[ℓ]
```

**Variant B** — `ℓ · d` bit ciphertexts (d = ⌈log₂(B+1)⌉):

```ts
const d = Math.ceil(Math.log2(B + 1));
const cts: Ciphertext[] = [];
const rs:  bigint[]     = [];
for (let j = 0; j < votes.length; j++) {
  for (let k = 0; k < d; k++) {
    const bit = (votes[j] >> BigInt(k)) & 1n;
    const { ct, r } = encrypt(bit, mpk);
    cts.push(ct);
    rs.push(r);
  }
}
```

### 2.3 Seed the ballot transcript

```ts
import { seedBallotTranscript } from '@shutter-network/shutter-voting-sdk';

const t = seedBallotTranscript(electionId, mpk, vk, cts, params);
```

The transcript must be passed by reference into every proof call below — the
prover and verifier derive the Fiat–Shamir challenges from the same running
hash.

### 2.4 Range / bit proofs

**Variant A** — one `(B+1)`-branch OR per candidate, candidate set
`{0, 1, …, B}`:

```ts
import { proveOR, rangeCandidates } from '@shutter-network/shutter-voting-sdk';

const candidates = rangeCandidates(B);                   // [0n, …, BigInt(B)]
const rangeOrBit = cts.map((ct, j) => {
  t.append('ballot:range', u16BE(j));                    // per-candidate tag
  return proveOR(
    { ct, mpk, candidates },
    { r: rs[j]!, trueIndex: Number(votes[j]!) },         // witness
    t,
  );
});
```

**Variant B** — one 2-branch OR per bit, candidate set `[0n, 1n]`:

```ts
const rangeOrBit = [];
for (let jk = 0; jk < cts.length; jk++) {
  const j = Math.floor(jk / d), k = jk % d;
  const bit = Number((votes[j]! >> BigInt(k)) & 1n) as 0 | 1;
  t.append('ballot:bit', u16BE(jk));
  rangeOrBit.push(
    proveOR(
      { ct: cts[jk]!, mpk, candidates: [0n, 1n] },
      { r: rs[jk]!, trueIndex: bit },
      t,
    ),
  );
}
```

`u16BE(n)` is a 2-byte big-endian encoding of the index — the verifier's copy
in `verifyBallot` uses the same label, so reproduce it verbatim. (The helper
is two lines; see `benchmarks/lib/ballot.ts` for the canonical copy.)

### 2.5 Budget proof

Compute the homomorphic ciphertext sum and the matching randomness sum:

**Variant A**

```ts
import { sumCts } from '@shutter-network/shutter-voting-sdk';
const ctSum = sumCts(cts);
const rSum  = rs.reduce((a, r) => a + r, 0n);
```

**Variant B** — weight each bit by `2^k`:

```ts
const weighted = cts.map((ct, i) => ({
  ct,
  r: rs[i]!,
  w: 1n << BigInt(i % d),
}));
const ctSum = weighted
  .map(({ ct, w }) => ({ c1: ct.c1.mul(w), c2: ct.c2.mul(w) }))
  .reduce((acc, cur) => ({
    c1: acc.c1.add(cur.c1),
    c2: acc.c2.add(cur.c2),
  }));
const rSum = weighted.reduce((a, { r, w }) => a + r * w, 0n);
```

Then:

```ts
import { proveBudgetExact, proveBudgetAtMost } from '@shutter-network/shutter-voting-sdk';

const V = votes.reduce((a, b) => a + b, 0n);
t.append('ballot:budget', new Uint8Array([0]));       // separator tag

const budget =
  params.mode === 'exact'
    ? proveBudgetExact(
        { ctSum, mpk, budget: BigInt(B) },
        { rSum },
        t,
      )
    : proveBudgetAtMost(
        { ctSum, mpk, budget: BigInt(B) },
        { rSum, V },
        t,
      );
```

### 2.6 Encode the ballot validity proof

```ts
import { encodeBallotValidityProof } from '@shutter-network/shutter-voting-sdk';

const bvp = {
  version: 0x01,
  variant: params.variant,   // 'A' | 'B'
  rangeOrBit,
  budget,
};
const zkProof = encodeBallotValidityProof(bvp);       // Uint8Array
```

### 2.7 Schnorr-sign the canonical preimage

```ts
import { canonicalBallotMessage, schnorrSign, encodeSchnorr } from '@shutter-network/shutter-voting-sdk';
import { keccak256 } from 'viem';

const ciphertextBytes: [Uint8Array, Uint8Array][] = cts.map(
  (ct) => [ct.c1.toBytes(), ct.c2.toBytes()],
);
const preimage = canonicalBallotMessage({
  electionId,
  pseudonym,
  ciphertexts: ciphertextBytes,
  zkProof,
});
const sig = schnorrSign(sk, vk, keccak256(preimage, 'bytes'));
const voterSignature = encodeSchnorr(sig);            // 80 bytes
```

### 2.8 Final submission payload

The voter hands off this exact `BallotInputs` shape to the Vote Registry:

```ts
const inputs: BallotInputs = {
  electionId,                 // bytes32
  pseudonym,                  // bytes32
  vk: vk.toBytes(),           // 48 bytes, compressed G₁
  ciphertexts: ciphertextBytes,
  zkProof,                    // encodeBallotValidityProof output
  voterSignature,             // encodeSchnorr output (80 B)
  wrAttestation,              // opaque WR-Server attestation bytes
};
```

> ⚠ After submission the voter **must discard `sk`, every `r_j`, and `votes`**.
> Retaining `r_j` would let anyone recovering it recompute each `Enc(v_j; r_j)`
> and deanonymise the ballot.

---

## 3. Ballot verifier (Vote Proxy / auditor)

The verifier has one entry point: `verifyBallot`. It validates the ZK proofs,
the homomorphic budget constraint, the Schnorr signature, and delegates the
WR-Server attestation check to a caller-supplied function.

```ts
import {
  verifyBallot,
  type BallotInputs,
  type BallotVerifyParams,
  type WRAttestationVerifier,
  type G2Point,
} from '@shutter-network/shutter-voting-sdk';

const verifyWR: WRAttestationVerifier = (
  electionId, pseudonym, vk, attestation,
) => {
  // Out-of-SDK scope. Implement per your WR-Server's signature scheme.
  return true;
};

const result = verifyBallot(
  inputs,     // exactly the BallotInputs the voter produced
  params,     // exactly the BallotVerifyParams from the Election Authority
  mpk,        // same G2Point the voter encrypted against
  verifyWR,
);

if (!result.ok) {
  console.error('reject:', result.reason);
} else {
  // Accept, admit to tally.
}
```

### What `verifyBallot` enforces

- `numCandidates`, `budget` in `[1, 65535]`; `mode ∈ {'exact','atMost'}`;
  `variant ∈ {'A','B'}`; Variant B's `d === ⌈log₂(B+1)⌉` exactly.
- `electionId.length === 32`, `pseudonym.length === 32`.
- `mpk` and decoded `vk` are not the identity (kills trivial-signature class).
- Ciphertext count matches `ℓ` (Variant A) or `ℓ·d` (Variant B).
- Each G₂ / G₁ decode succeeds with subgroup check.
- `verifyWR(...)` returns true.
- Each range/bit OR proof verifies against the same transcript the prover seeded.
- The budget proof verifies on the homomorphic `ctSum` (Variant A) or on
  `ĉ = Σ_j Σ_k 2^k · c_{j,k}` (Variant B).
- The Schnorr signature verifies against `vk` and `keccak256(canonicalBallotMessage(...))`.

### What `verifyBallot` does **not** do

- It does not verify keyper shares (use `verifyDecryptionShare`).
- It does not pairing-check anything — no `verifyPairing` pass exists in this SDK.
- It does not check that `pseudonym` has not voted twice — the caller-supplied
  registry layer must enforce that.

---

## 4. Keyper (committee member)

Each keyper holds one secret share `msk_k` from the DKG and its index `k`
(1-based). After the voting phase closes, the tally contract publishes the
homomorphic sum of all admitted ciphertexts (per candidate). For **each**
`ctSum_j`, the keyper does exactly one call:

```ts
import {
  partialDecrypt,
  Transcript,
  type Ciphertext,
  type G2Point,
} from '@shutter-network/shutter-voting-sdk';

// Per-candidate inputs — `ctSum_j` is the homomorphic sum over all admitted
// ballots of that candidate's ciphertext column.
const t = new Transcript('SHUTTER-VOTE-DECRYPT-v1');
// Bind whatever election-level context both keyper and verifier agree on:
t.append('electionId', electionId);
t.append('candidate',  u16BE(j));   // or your own scheme

const share = partialDecrypt(
  ctSum_j,       // Ciphertext
  msk_k,         // bigint — NEVER leaves keyper custody
  mpk_k,         // G2Point — = msk_k · P₂, on chain as committeePKs[k-1]
  k,             // number — 1-based keyper index (== evaluation point α_k)
  t,             // Transcript (consumed)
);
// share: PartialDecryption { keyperIndex, sigma, proof }
```

The `share` is published on chain; any tally aggregator or auditor can
re-verify it using the same transcript seeding.

> **Keypers do not call anything else in this SDK.** DKG, share storage, and
> keyper networking are intentionally out of scope.

---

## 5. Tally Aggregator

The aggregator collects at least `t + 1` partial decryptions per candidate,
verifies each, Lagrange-combines them to `τ_j = V_j · P₂`, and BSGS-recovers
`V_j ∈ [0, ℓ·B]` (upper bound set by the Election Authority).

### 5.1 Verify each keyper share

```ts
import {
  verifyDecryptionShare,
  Transcript,
} from '@shutter-network/shutter-voting-sdk';

// The aggregator must seed its Transcript *identically* to the keyper's:
function makeShareTranscript(electionId: Uint8Array, j: number) {
  const t = new Transcript('SHUTTER-VOTE-DECRYPT-v1');
  t.append('electionId', electionId);
  t.append('candidate',  u16BE(j));
  return t;
}

const good = verifyDecryptionShare(
  ctSum_j,
  share,                               // PartialDecryption from chain
  mpk_k,                               // committeePKs[share.keyperIndex - 1]
  makeShareTranscript(electionId, j),
);
if (!good) throw new Error('bad share from keyper ' + share.keyperIndex);
```

### 5.2 Combine a threshold subset

Pick any `t + 1` verified shares. The evaluation points **must** match the
keyper indices one-for-one — mismatch throws.

```ts
import { combineShares } from '@shutter-network/shutter-voting-sdk';

const selected = verifiedShares.slice(0, threshold + 1);
const alphas   = selected.map((s) => BigInt(s.keyperIndex));
const tauJ     = combineShares(selected, alphas, ctSum_j);  // G2Point
```

### 5.3 Recover the integer tally

Build the BSGS baby-step table **once** per election and reuse across all
candidates; per-candidate recovery is then a fast lookup.

```ts
import {
  buildBabyStepTable,
  recoverDiscreteLogWithTable,
} from '@shutter-network/shutter-voting-sdk';

const upperBound = BigInt(numBallots) * BigInt(B);    // ≥ max possible V_j
const table = buildBabyStepTable(upperBound);

for (let j = 0; j < numCandidates; j++) {
  const V_j = recoverDiscreteLogWithTable(tauJ[j], table);  // bigint
  console.log('candidate', j, 'got', V_j, 'votes');
}
```

If you only have one tally to run, the single-call form is:

```ts
import { recoverDiscreteLog } from '@shutter-network/shutter-voting-sdk';
const V_j = recoverDiscreteLog(tauJ, upperBound);
```

`recoverDiscreteLog*` throws if the recovered value exceeds `upperBound` —
that is a tally-layer bug (admitted ballots whose sum exceeds the declared
bound), not a retry condition.

---

## Summary — function → caller matrix

| SDK export                          | Election Auth. | Voter | Ballot Verifier | Keyper | Tally Agg. |
| ----------------------------------- |:--------------:|:-----:|:---------------:|:------:|:----------:|
| `initCurves`                        |                |   ✅  |       ✅        |   ✅   |     ✅     |
| `schnorrKeygen`                     |                |   ✅  |                 |        |            |
| `encrypt`                           |                |   ✅  |                 |        |            |
| `sumCts` / `addCt` / `scalarMulCt`  |                |   ✅  |                 |        |  (if needed) |
| `seedBallotTranscript`              |                |   ✅  |   (internal)    |        |            |
| `rangeCandidates`                   |                |   ✅  |   (internal)    |        |            |
| `proveOR`                           |                |   ✅  |                 |        |            |
| `proveBudgetExact` / `…AtMost`      |                |   ✅  |                 |        |            |
| `encodeBallotValidityProof`         |                |   ✅  |                 |        |            |
| `canonicalBallotMessage`            |                |   ✅  |   (internal)    |        |            |
| `schnorrSign` / `encodeSchnorr`     |                |   ✅  |                 |        |            |
| `verifyBallot`                      |                |       |       ✅        |        |            |
| `Transcript` (constructor)          |                |       |                 |   ✅   |     ✅     |
| `partialDecrypt`                    |                |       |                 |   ✅   |            |
| `verifyDecryptionShare`             |                |       |                 |        |     ✅     |
| `combineShares`                     |                |       |                 |        |     ✅     |
| `buildBabyStepTable`                |                |       |                 |        |     ✅     |
| `recoverDiscreteLog` / `…WithTable` |                |       |                 |        |     ✅     |

Everything else exported from `@shutter-network/shutter-voting-sdk` (the
`G1Point` / `G2Point` types, `DLEQProof` / `ORProof` types, `encodeDLEQ` /
`decodeDLEQ`) is supporting surface for the above calls — no actor invokes
them directly in the happy path.
