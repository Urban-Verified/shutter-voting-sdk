# Shutter Voting SDK

TypeScript SDK for client-side encrypted voting on the Shutter Network. Implements linearly homomorphic threshold ElGamal over BLS12-381 with zero-knowledge proofs of vote validity and correct partial decryption, per the Munich *Personalratswahl* cryptographic protocol specification.

Forked from [`@shutter-network/shutter-sdk`](https://github.com/shutter-network/shutter-sdk); shares the BLST WASM layer.

> **Status.** Early development — API not yet stable. This README describes the full intended surface of the SDK; not every function below is implemented in every release. See [docs/development-plan.md](docs/development-plan.md) for the current phase breakdown.

---

## Table of contents

- [What this SDK is (and isn't)](#what-this-sdk-is-and-isnt)
- [Install & setup](#install--setup)
- [Asset placement (browser)](#asset-placement-browser)
- [High-level flow](#high-level-flow)
- [API surface](#api-surface)
  - [Curve & scalar primitives](#curve--scalar-primitives)
  - [Hash-to-scalar / hash-to-curve](#hash-to-scalar--hash-to-curve)
  - [Fiat–Shamir transcript](#fiatshamir-transcript)
  - [ElGamal encryption & homomorphic ops](#elgamal-encryption--homomorphic-ops)
  - [Schnorr signatures](#schnorr-signatures)
  - [Zero-knowledge proofs](#zero-knowledge-proofs)
  - [Ballot validity proofs](#ballot-validity-proofs)
  - [Ballot-level verification](#ballot-level-verification)
  - [Wire codecs](#wire-codecs)
  - [Keyper partial decryption](#keyper-partial-decryption)
  - [Aggregation & tally recovery](#aggregation--tally-recovery)
- [Variants A and B](#variants-a-and-b)
- [Security notes](#security-notes)
- [Testing & building](#testing--building)
- [References](#references)

---

## What this SDK is (and isn't)

**In scope**

- ElGamal encryption in G₂ on BLS12-381, with homomorphic addition, scalar multiplication, and a canonical sum.
- Schnorr signatures in G₁ for voter-to-ballot binding.
- A Fiat–Shamir `Transcript` type with Merlin-style challenge fold-back.
- Zero-knowledge proofs: Chaum–Pedersen DLEQ, OR-composition, exact-budget, at-most-budget, ballot validity.
- Ballot-level verification (`verifyBallot`) that composes all of the above.
- Wire codecs for the opaque `bytes` fields the on-chain contract leaves unspecified: `zkProof`, Schnorr signature, decryption-share DLEQ.
- **One** keyper primitive — `partialDecrypt` — plus share verification, Lagrange combination, and baby-step-giant-step (BSGS) discrete-log recovery for the final tally.

**Out of scope**

- Distributed key generation (DKG), keyper key storage, keyper networking/orchestration.
- Contract-struct types or any ABI layer — the consumer owns their `Ballot` / `ElectionConfig` / `DecryptionShare` shapes and destructures them into the primitive-typed inputs the SDK expects.
- `Voter` / `Keyper` classes or service wrappers. The SDK exposes plain functions; callers compose what they need.
- WR-Server attestation verification — you inject a `WRAttestationVerifier` closure into `verifyBallot`.

---

## Install & setup

```bash
npm install @shutter-network/shutter-voting-sdk viem
```

`viem` is used for `keccak256`. The SDK depends on a BLST WASM build; it must be initialised once at startup before any curve or proof call:

```ts
import { initCurves } from '@shutter-network/shutter-voting-sdk';

await initCurves();
```

## Asset placement (browser)

If you use this SDK in a browser, `blst.js` and `blst.wasm` must be reachable at `/blst.js` and `/blst.wasm`. Both files ship in `dist/`.

```
my-app/
├── public/
│   ├── blst.js
│   └── blst.wasm
```

### Vite

```ts
export default defineConfig({
  optimizeDeps: {
    exclude: ['@shutter-network/shutter-voting-sdk'],
  },
});
```

---

## High-level flow

A Munich-style ballot passes through these stages:

1. **Voter (browser).** For each of `ℓ` candidates, pick a vote `v_j ∈ {0,…,B}`, encrypt it under the master public key `mpk`, then produce a `BallotValidityProof` (per-candidate range proof + aggregate budget proof) and sign a canonical preimage with Schnorr.
2. **Vote Proxy / auditor.** Call `verifyBallot`, which decodes the proof, runs every range proof, aggregates the ciphertexts, verifies the budget proof on the sum, and checks the Schnorr signature.
3. **Tally Aggregator.** Homomorphically sum active per-voter ciphertexts per candidate.
4. **Keypers (≥ t+1).** Each keyper calls `partialDecrypt(ctSum, …)` to publish an on-chain decryption share with a DLEQ proof binding the share to their committee public key.
5. **Tally Aggregator / auditor.** `verifyDecryptionShare` each share, `combineShares` via Lagrange interpolation, then `recoverDiscreteLog` (BSGS in G₂) to obtain the plaintext candidate totals.

---

## API surface

All exports below come from the package root:

```ts
import { /* … */ } from '@shutter-network/shutter-voting-sdk';
```

### Curve & scalar primitives

```ts
class G1Point {
  static generator(): G1Point;
  static fromBytes(bytes: Uint8Array): G1Point; // 48-byte compressed; runs subgroup check
  toBytes(): Uint8Array; // 48 bytes
  add(other: G1Point): G1Point;
  mul(scalar: bigint): G1Point;
  equals(other: G1Point): boolean;
}

class G2Point {
  static generator(): G2Point;
  static fromBytes(bytes: Uint8Array): G2Point; // 96-byte compressed; runs subgroup check
  toBytes(): Uint8Array; // 96 bytes
  add(other: G2Point): G2Point;
  mul(scalar: bigint): G2Point;
  equals(other: G2Point): boolean;
}

const G1_BYTES = 48;
const G2_BYTES = 96;

// Scalar field Z_Q (Q = BLS12-381 group order).
const Q: bigint;
const SCALAR_BYTES = 32;

function randomScalar(): bigint;            // uniform in [0, Q)
function modQ(x: bigint): bigint;           // reduce into [0, Q)
function wideReduce(wide: Uint8Array): bigint; // reduce a ≥48-byte buffer
function scalarInv(x: bigint): bigint;      // x^(-1) mod Q

function bytesToBigIntBE(b: Uint8Array): bigint;
function bigIntToBytesBE(x: bigint, size: number): Uint8Array;
function scalarToBytes(x: bigint): Uint8Array;   // 32-byte BE
function scalarFromBytes(b: Uint8Array): bigint; // rejects ≥ Q
```

### Hash-to-scalar / hash-to-curve

Domain-separated hashing used by every Fiat–Shamir challenge and every hash-to-curve path.

```ts
function hashToScalar(dst: Uint8Array, ...msgs: Uint8Array[]): bigint;

const DST_FIAT_SHAMIR: Uint8Array;
const DST_HASH_TO_CURVE_G1: Uint8Array;
const DST_HASH_TO_CURVE_G2: Uint8Array;
```

### Fiat–Shamir transcript

Merlin-style, length-prefixed, with automatic challenge fold-back — the transcript is the single source of truth for every challenge in every proof.

```ts
class Transcript {
  constructor(label: string);
  append(tag: string, bytes: Uint8Array): void;
  appendScalar(tag: string, x: bigint): void;
  appendPoint(tag: string, p: G1Point | G2Point): void;
  challenge(tag: string): bigint; // folds the challenge back into the transcript
  clone(): Transcript;
}
```

### ElGamal encryption & homomorphic ops

Linearly homomorphic threshold ElGamal in G₂:

```
C1 = r · P₂
C2 = r · mpk + m · P₂
```

```ts
interface Ciphertext {
  c1: G2Point;
  c2: G2Point;
}

function encrypt(m: bigint, mpk: G2Point, r?: bigint): { ct: Ciphertext; r: bigint };
function addCt(a: Ciphertext, b: Ciphertext): Ciphertext;
function scalarMulCt(a: Ciphertext, k: bigint): Ciphertext;
function sumCts(cts: readonly Ciphertext[]): Ciphertext;
```

`r` is optional; omitting it draws a fresh scalar. The returned `r` is the randomness the prover re-uses as the witness for range and budget proofs.

### Schnorr signatures

Standard single-point Schnorr over G₁. Used to bind a ballot to a voter's ephemeral verification key `vk = sk · P₁`.

```ts
interface SchnorrSig {
  R: G1Point;
  s: bigint;
}

function schnorrKeygen(): { sk: bigint; vk: G1Point };
function schnorrSign(sk: bigint, vk: G1Point, msg: Uint8Array, k?: bigint): SchnorrSig;
function schnorrVerify(vk: G1Point, msg: Uint8Array, sig: SchnorrSig): boolean;
```

The signed `msg` is the `keccak256` of the bytes returned by [`canonicalBallotMessage`](#ballot-level-verification) — don't assemble the preimage by hand.

### Zero-knowledge proofs

All proofs share one transcript pattern: build a `Transcript`, append public inputs, pass it to the prover / verifier, and the same transcript is re-used for downstream proofs. Proofs are deterministic given injected commitment randomness (see the optional `commit` params), which keeps test vectors and fuzzing tractable.

```ts
interface DLEQProof  { e: bigint; z: bigint; }
interface ORProofBranch { a1: G2Point; a2: G2Point; e: bigint; z: bigint; }
interface ORProof    { branches: ORProofBranch[]; }

type BudgetProof =
  | { mode: 'exact'; proof: DLEQProof }
  | { mode: 'atMost'; proof: ORProof };
```

**Chaum–Pedersen DLEQ** — proves `logBase1(point1) == logBase2(point2)` without revealing the discrete log.

```ts
interface DLEQStatement { base1: G2Point; point1: G2Point; base2: G2Point; point2: G2Point; }
interface DLEQWitness   { x: bigint; }

function proveDLEQ(stmt: DLEQStatement, witness: DLEQWitness, t: Transcript, commit?: { w?: bigint }): DLEQProof;
function verifyDLEQ(stmt: DLEQStatement, proof: DLEQProof, t: Transcript): boolean;
```

**OR composition** — proves a ciphertext `(C1, C2)` encrypts *one* of a fixed candidate set without revealing which.

```ts
interface ORStatement { ct: Ciphertext; mpk: G2Point; candidates: readonly bigint[]; }
interface ORWitness   { r: bigint; trueIndex: number; }
interface ORCommitments { w?: bigint; simulated?: ReadonlyArray<{ e: bigint; z: bigint } | undefined>; }

function proveOR(stmt: ORStatement, witness: ORWitness, t: Transcript, commit?: ORCommitments): ORProof;
function verifyOR(stmt: ORStatement, proof: ORProof, t: Transcript): boolean;
```

**Budget proofs** — two wrappers over DLEQ / OR that bind the aggregate ciphertext `cΣ = Σ_j c_j` to a budget `B`. The mode byte is bound into the transcript, so an `exact` proof cannot be reinterpreted as an `atMost` proof even when `V = B`.

```ts
interface BudgetStatement    { ctSum: Ciphertext; mpk: G2Point; budget: bigint; }
interface ExactBudgetWitness { rSum: bigint; }
interface AtMostBudgetWitness { rSum: bigint; V: bigint; }

function proveBudgetExact (stmt: BudgetStatement, w: ExactBudgetWitness,  t: Transcript, commit?: { w?: bigint }): BudgetProof;
function proveBudgetAtMost(stmt: BudgetStatement, w: AtMostBudgetWitness, t: Transcript, commit?: ORCommitments): BudgetProof;

function verifyBudgetExact (stmt: BudgetStatement, proof: BudgetProof, t: Transcript): boolean;
function verifyBudgetAtMost(stmt: BudgetStatement, proof: BudgetProof, t: Transcript): boolean;
function verifyBudget      (stmt: BudgetStatement, proof: BudgetProof, t: Transcript): boolean; // dispatch on proof.mode
```

### Ballot validity proofs

A `BallotValidityProof` bundles every per-candidate range / bit proof and the aggregate budget proof into one object, wire-encodable as a single `bytes` field on the ballot.

```ts
interface BallotValidityProof {
  version: number;         // 0x01
  variant: 'A' | 'B';
  rangeOrBit: ORProof[];   // Variant A: ℓ proofs each with B+1 branches.
                           // Variant B: ℓ·d bit proofs each with 2 branches.
  budget: BudgetProof;
}
```

See [Variants A and B](#variants-a-and-b) for when to pick each.

### Ballot-level verification

`verifyBallot` is the one-call entry point for Vote Proxy / auditor roles. It decodes the `zkProof`, validates every sub-proof, checks the homomorphic sum against the budget, verifies the Schnorr signature, and invokes a caller-supplied WR-Server attestation verifier.

```ts
interface BallotInputs {
  electionId: Uint8Array;                              // bytes32
  pseudonym:  Uint8Array;                              // bytes32 nym_i
  vk:         Uint8Array;                              // 48-byte compressed G₁
  ciphertexts: ReadonlyArray<readonly [Uint8Array, Uint8Array]>; // each pair = (C1, C2), 96 bytes each
  zkProof:        Uint8Array;                          // encodeBallotValidityProof output
  voterSignature: Uint8Array;                          // encodeSchnorr output (80 bytes)
  wrAttestation:  Uint8Array;                          // opaque σ_WR — handed to your verifier
}

interface BallotVerifyParams {
  numCandidates: number;                               // ℓ
  budget:        number;                               // B
  mode:    'exact' | 'atMost';
  variant: 'A' | 'B';
  d?: number;                                          // Variant B only: ⌈log2(B+1)⌉
}

type WRAttestationVerifier = (
  electionId: Uint8Array,
  pseudonym:  Uint8Array,
  vk:         Uint8Array,
  attestation: Uint8Array,
) => boolean;

type VerifyResult = { ok: true } | { ok: false; reason: string };

function verifyBallot(
  inputs: BallotInputs,
  params: BallotVerifyParams,
  mpk: G2Point,
  verifyWRAttestation: WRAttestationVerifier,
): VerifyResult;

// Canonical Schnorr preimage — use this on both the signer and verifier sides.
function canonicalBallotMessage(args: {
  electionId: Uint8Array;
  pseudonym:  Uint8Array;
  ciphertexts: ReadonlyArray<readonly [Uint8Array, Uint8Array]>;
  zkProof:    Uint8Array;
}): Uint8Array;

// Shared transcript seeding used by both prover and verifier.
function seedBallotTranscript(
  electionId: Uint8Array,
  mpk: G2Point,
  vk: G1Point,
  ciphertexts: readonly Ciphertext[],
  params: BallotVerifyParams,
): Transcript;

// Candidate set for a Variant A range proof: [0n, 1n, …, Bn].
function rangeCandidates(budget: number): bigint[];
```

Destructure your own `Ballot` struct (from your ABI / contract layer) into `BallotInputs`; the SDK does not own any contract-shaped type. Passing the raw byte fields lets the consumer pick any serializer (ethers, viem, abitype) without coupling to ours.

### Wire codecs

The only SDK-owned serialisation surface — the `bytes` fields the on-chain contract leaves opaque.

```ts
const BVP_VERSION: 0x01;
const SCHNORR_BYTES: 80;

interface DecodeParams {
  variant: 'A' | 'B';
  numCandidates: number;
  budget: number;
  d?: number; // Variant B only
}

function encodeBallotValidityProof(p: BallotValidityProof): Uint8Array;
function decodeBallotValidityProof(buf: Uint8Array, params: DecodeParams): BallotValidityProof;

function encodeDLEQ(p: DLEQProof): Uint8Array;              // 64 bytes: 32-BE e ‖ 32-BE z
function decodeDLEQ(b: Uint8Array): DLEQProof;

function encodeSchnorr(sig: SchnorrSig): Uint8Array;         // 80 bytes: 48-byte R ‖ 32-BE s
function decodeSchnorr(b: Uint8Array): SchnorrSig;
```

Decoders are strict: wrong version, wrong length, trailing bytes, or mismatched `(numCandidates, budget, variant)` all throw.

### Keyper partial decryption

The keyper's entire import surface. DKG, key storage, and share transport remain keyper-infrastructure concerns.

```ts
interface PartialDecryption {
  sigma: G2Point;    // σ_{k,j} = msk_k · C1
  proof: DLEQProof;  // DLEQ tying σ to committeePK = msk_k · P₂
  keyperIndex: number;
}

function partialDecrypt(
  ctSum: Ciphertext,
  msk_k: bigint,
  mpk_k: G2Point,
  keyperIndex: number,
  t: Transcript,
): PartialDecryption;

function verifyDecryptionShare(
  ctSum: Ciphertext,
  share: PartialDecryption,
  committeePK: G2Point,
  t: Transcript,
): boolean;
```

### Aggregation & tally recovery

```ts
// Lagrange-combine any t+1 verified shares → τ = C2 − σ.
function combineShares(
  shares: PartialDecryption[],
  evaluationPoints: bigint[],
  ctSum: Ciphertext,
): G2Point;

// Baby-step-giant-step in G₂: find T such that τ = T · P₂.
// Runtime & memory O(√upperBound). Munich-scale: ~10^5 upper bound → sub-second.
function recoverDiscreteLog(tau: G2Point, upperBound: bigint): bigint;
```

---

## Variants A and B

Two range-proof shapes are supported, picked at election-config time:

| Variant | Per-candidate proof        | Branches | Ballot proof size | When to pick                                                  |
|---------|----------------------------|----------|-------------------|---------------------------------------------------------------|
| **A**   | `(B+1)`-branch OR over {0,…,B} | `B+1`    | `ℓ · (B+1)` OR branches | Small budgets `B` (Munich default).                           |
| **B**   | `d` bit-proofs over {0,1}, where `d = ⌈log2(B+1)⌉` | `2`      | `ℓ · d` OR branches   | Large budgets where `(B+1) > d`, i.e. `B ≥ 3` or so.          |

Variant B is declared in the type surface today; the prover / verifier / codec for it ship in a later phase (P4c). Calling Variant B paths before then throws an explicit `"Variant B not implemented"` error rather than failing silently.

---

## Security notes

- **Always call `initCurves()` before anything else.** Every point and proof path assumes the WASM layer is live.
- **Subgroup checks are automatic.** `G1Point.fromBytes` / `G2Point.fromBytes` reject non-subgroup points, so `verifyBallot` gets them for free when decoding `vk` and ciphertexts.
- **Don't reconstruct the Schnorr preimage by hand.** Always call `canonicalBallotMessage` on both the signer and verifier side. Any drift silently invalidates every ballot.
- **Transcript binding is load-bearing.** `seedBallotTranscript` binds `vk`, `electionId`, `mpk`, variant / mode / budget, and every ciphertext. Skipping any of these enables cross-ballot replay.
- **The SDK never sees your contract structs.** Destructure your own `Ballot` and `ElectionConfig` into the primitive shapes. No contract-struct mirror lives here by design (see D-5 in the dev plan).
- **WR-Server attestation is out of scope.** Inject a `WRAttestationVerifier` closure — the SDK never tries to guess your attestation scheme.

---

## Testing & building

```bash
npm test        # jest
npm run build   # tsup + copies blst.wasm into dist/
```

Benchmarks (proof gen / verify timings, proof sizes per variant) live in `benchmarks/`.

---

## References

- Munich *Personalratswahl* cryptographic protocol specification (v0.3).
- Potential Extensions document (Variant B, binary decomposition, WR-Server integration).
- [docs/development-plan.md](docs/development-plan.md) — phase-by-phase implementation plan, deviations, and rationale.
