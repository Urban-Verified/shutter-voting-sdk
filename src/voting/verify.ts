/**
 * Ballot-level verification (Munich spec §6 composition).
 *
 * `verifyBallot` composes the pieces built in P1–P3b: decodes the opaque
 * `zkProof` bytes, runs each candidate's range proof, homomorphically sums
 * the ciphertexts, runs the budget proof on the sum, and checks the
 * voter's Schnorr signature over a canonical preimage.
 *
 * `canonicalBallotMessage` is the single source of truth for what bytes the
 * voter actually signs; both the frontend signer and any verifier (Vote
 * Proxy, auditor) must call this function rather than assembling the
 * preimage themselves, because any drift breaks every ballot.
 *
 * Per deviation D-5, nothing in this file references contract-struct
 * types. Callers destructure their own `Ballot` into the primitive-typed
 * `BallotInputs` shape and pass it in.
 */

import { keccak256 } from 'viem';

import {
  G1Point,
  G2Point,
} from '../crypto/curve';
import {
  decodeBallotValidityProof,
  decodeSchnorr,
} from '../contract/codec';
import { addCt, scalarMulCt, sumCts } from './encrypt';
import {
  type ORStatement,
  verifyBudget,
  verifyOR,
} from './proofs';
import { schnorrVerify } from './schnorr';
import { verifyAttestation, type Attestation } from './attestation';
import { Transcript } from './transcript';
import type {
  BallotValidityProof,
  Ciphertext,
} from './types';

const encoder = new TextEncoder();

/**
 * v2 folds the eligibility credential into the signed ballot message.
 *
 * Under v1 the credential could not live in the ballot — the slot for it was an
 * opaque `wrAttestation` blob that was not covered by this message — so consumers
 * carried it alongside and bound it with a *second* Schnorr signature over a separate
 * `SHUTTER-VOTE-BINDING-v1` transcript. That transcript ended up implemented four
 * times across two languages, all of which had to agree byte-for-byte.
 *
 * Bumping the label is what makes the change detectable: a v1 signature checked
 * against a v2 message does not fail informatively, it just returns false, which reads
 * as "wrong voter" rather than "wrong format". Verifiers should re-check against v1 on
 * the failure path and say so.
 */
const BALLOT_MESSAGE_LABEL = 'SHUTTER-VOTE-BALLOT-v2';
const CANONICAL_HEADER = encoder.encode(BALLOT_MESSAGE_LABEL);

/**
 * The Fiat–Shamir transcript label for the range/budget proofs — a **different domain**
 * from the signed message above, not an older version of it.
 *
 * These were one constant. Bumping the message to v2 therefore changed every proof's
 * challenge as a side effect, which is a bug: the two version for unrelated reasons.
 * The message changed because the credential moved inside it; the proof still proves
 * the same statement over the same public inputs and its domain never changed.
 */
const BALLOT_PROOF_TRANSCRIPT_LABEL = 'SHUTTER-VOTE-BALLOT-PROOF-v1';

/** The superseded message format, for the v1 detection on the failure path only. */
const BALLOT_MESSAGE_LABEL_V1 = 'SHUTTER-VOTE-BALLOT-v1';

/**
 * The three ballot domain separators, exported for the guard test that asserts they
 * stay distinct. Only the first two are versions of each other.
 */
export const BALLOT_LABELS = {
  message: BALLOT_MESSAGE_LABEL,
  proofTranscript: BALLOT_PROOF_TRANSCRIPT_LABEL,
  supersededMessage: BALLOT_MESSAGE_LABEL_V1,
} as const;

// ---------- Public input shapes ----------

/**
 * Primitive-typed ballot inputs — the caller's `Ballot` struct destructured
 * into raw bytes. The SDK does not know about contract-struct types, so
 * every point / signature / attestation is passed as its on-wire byte
 * string and decoded internally.
 */
export interface BallotInputs {
  electionId: Uint8Array; // bytes32
  pseudonym: Uint8Array; // bytes32 nym_i
  vk: Uint8Array; // 48-byte compressed G₁
  ciphertexts: ReadonlyArray<readonly [Uint8Array, Uint8Array]>; // (C1, C2) pairs, each 96 bytes compressed G₂
  zkProof: Uint8Array; // output of encodeBallotValidityProof
  voterSignature: Uint8Array; // encodeSchnorr(sig) — 80 bytes
  /** The eligibility credential, verified here and covered by `voterSignature`. */
  attestation: Attestation;
}

/**
 * Election-side parameters the ballot verifier needs. A subset of the
 * consumer's `ElectionConfig` — only the fields that actually feed into
 * ballot verification appear here, so the SDK never sees
 * `phaseDeadlines` / `keyperAddresses` / etc.
 */
export interface BallotVerifyParams {
  numCandidates: number; // ℓ
  budget: number; // B
  mode: 'exact' | 'atMost';
  variant: 'A' | 'B';
  d?: number; // Variant B only
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; reason: string };

/** Constant-time-enough byte comparison for fixed-size public values. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// ---------- Canonical Schnorr preimage ----------

/**
 * Deterministic preimage for the voter's Schnorr signature. Both the
 * frontend (when signing) and any verifier (Vote Proxy, auditor) MUST
 * call this function rather than reconstructing the concatenation
 * manually — any drift in byte ordering or length prefixes silently
 * invalidates every ballot.
 *
 * Layout:
 *   "SHUTTER-VOTE-BALLOT-v2" ‖ electionId ‖ pseudonym
 *     ‖ u16 BE ciphertexts.length
 *     ‖ for each (C1, C2): C1 bytes ‖ C2 bytes      // already 96-byte compressed
 *     ‖ u32 BE zkProof.length ‖ zkProof
 *     ‖ attestation.pseudonym ‖ attestation.vk       // 32 ‖ 48
 *     ‖ u256 BE weight ‖ u256 BE nonce
 *     ‖ u16 BE attestation.signature.length ‖ signature
 *
 * The credential's own `electionId` is not repeated — the message already opens with
 * it, and `verifyBallot` rejects an attestation naming a different election.
 *
 * The issuer's **signature bytes are covered**, not just the credential's fields.
 * Schnorr signing is randomized (`schnorrSign` draws `k` at random), so one set of
 * fields has many valid signatures; leaving the bytes uncovered would let a relay swap
 * one valid signature for another and keep the voter's signature valid. Semantically
 * harmless, but it makes the envelope malleable — and the published ballot feed is
 * re-aggregated byte-for-byte by auditors, and ballot digests are used as stable
 * identifiers for duplicate detection and re-vote ordering. Both need the bytes fixed.
 *
 * The caller hashes the returned preimage (keccak256) before handing it
 * to `schnorrSign` / `schnorrVerify`.
 */
export function canonicalBallotMessage(args: {
  electionId: Uint8Array;
  pseudonym: Uint8Array;
  ciphertexts: ReadonlyArray<readonly [Uint8Array, Uint8Array]>;
  zkProof: Uint8Array;
  attestation: Attestation;
}): Uint8Array {
  if (args.electionId.length !== 32) {
    throw new Error(
      `canonicalBallotMessage: electionId must be exactly 32 bytes (got ${args.electionId.length})`,
    );
  }
  if (args.pseudonym.length !== 32) {
    throw new Error(
      `canonicalBallotMessage: pseudonym must be exactly 32 bytes (got ${args.pseudonym.length})`,
    );
  }
  for (const [c1, c2] of args.ciphertexts) {
    if (c1.length !== 96 || c2.length !== 96) {
      throw new Error('canonicalBallotMessage: each ciphertext component must be 96 bytes');
    }
  }
  const att = args.attestation;
  if (att.pseudonym.length !== 32) {
    throw new Error(
      `canonicalBallotMessage: attestation.pseudonym must be exactly 32 bytes (got ${att.pseudonym.length})`,
    );
  }
  if (att.vk.length !== 48) {
    throw new Error(
      `canonicalBallotMessage: attestation.vk must be exactly 48 bytes (got ${att.vk.length})`,
    );
  }
  if (att.weight < 0n || att.nonce < 0n) {
    throw new Error('canonicalBallotMessage: attestation weight/nonce must be non-negative');
  }
  const n = args.ciphertexts.length;
  const size =
    CANONICAL_HEADER.length +
    args.electionId.length +
    args.pseudonym.length +
    2 +
    n * (96 + 96) +
    4 +
    args.zkProof.length +
    32 + // attestation.pseudonym
    48 + // attestation.vk
    32 + // weight,  u256 BE
    32 + // nonce,   u256 BE
    2 + // u16 BE signature length
    att.signature.length;
  const out = new Uint8Array(size);
  let o = 0;
  out.set(CANONICAL_HEADER, o);
  o += CANONICAL_HEADER.length;
  out.set(args.electionId, o);
  o += args.electionId.length;
  out.set(args.pseudonym, o);
  o += args.pseudonym.length;
  out[o++] = (n >>> 8) & 0xff;
  out[o++] = n & 0xff;
  for (const [c1, c2] of args.ciphertexts) {
    out.set(c1, o);
    o += 96;
    out.set(c2, o);
    o += 96;
  }
  const zpLen = args.zkProof.length;
  out[o++] = (zpLen >>> 24) & 0xff;
  out[o++] = (zpLen >>> 16) & 0xff;
  out[o++] = (zpLen >>> 8) & 0xff;
  out[o++] = zpLen & 0xff;
  out.set(args.zkProof, o);
  o += args.zkProof.length;

  // ---- the eligibility credential (v2) ----
  out.set(att.pseudonym, o);
  o += 32;
  out.set(att.vk, o);
  o += 48;
  // Fixed 32-byte big-endian, not a minimal encoding: a variable-length integer would
  // make the concatenation ambiguous without its own length prefix, and weight can
  // legitimately exceed 2^53 now that voting power is uncapped.
  writeU256BE(out, o, att.weight);
  o += 32;
  writeU256BE(out, o, att.nonce);
  o += 32;
  const sigLen = att.signature.length;
  if (sigLen > 0xffff) {
    throw new Error(`canonicalBallotMessage: attestation.signature too long (${sigLen})`);
  }
  out[o++] = (sigLen >>> 8) & 0xff;
  out[o++] = sigLen & 0xff;
  out.set(att.signature, o);
  return out;
}

/**
 * The v1 ballot preimage — diagnostic only, never accepted.
 *
 * Its single caller is the failure path in `verifyBallot`, so that a ballot signed by
 * a pre-v2 client is reported as a format mismatch rather than as an invalid
 * signature. Deliberately a separate function rather than a flag on
 * `canonicalBallotMessage`: a parameter that switches a signed format between
 * versions is one mistaken argument away from accepting the old one.
 */
function preV1BallotMessage(inputs: BallotInputs): Uint8Array {
  const header = encoder.encode(BALLOT_MESSAGE_LABEL_V1);
  const n = inputs.ciphertexts.length;
  const size =
    header.length + 32 + 32 + 2 + n * 192 + 4 + inputs.zkProof.length;
  const out = new Uint8Array(size);
  let o = 0;
  out.set(header, o);
  o += header.length;
  out.set(inputs.electionId, o);
  o += 32;
  out.set(inputs.pseudonym, o);
  o += 32;
  out[o++] = (n >>> 8) & 0xff;
  out[o++] = n & 0xff;
  for (const [c1, c2] of inputs.ciphertexts) {
    out.set(c1, o);
    o += 96;
    out.set(c2, o);
    o += 96;
  }
  const zpLen = inputs.zkProof.length;
  out[o++] = (zpLen >>> 24) & 0xff;
  out[o++] = (zpLen >>> 16) & 0xff;
  out[o++] = (zpLen >>> 8) & 0xff;
  out[o++] = zpLen & 0xff;
  out.set(inputs.zkProof, o);
  return out;
}

/** Big-endian 32-byte write, so weights past 2^53 survive the encoding. */
function writeU256BE(out: Uint8Array, at: number, value: bigint): void {
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[at + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

// ---------- Transcript seeding (shared between prover and verifier) ----------

/**
 * Seed a ballot-level Fiat–Shamir transcript with every public input
 * that binds the subsequent range / budget proofs. The prover and the
 * verifier MUST build this transcript identically — in particular, the
 * proof's soundness depends on `vk` being one of the bound values, which
 * is how a ballot produced for voter V1 is prevented from being
 * replayed under V2's `vk` (Munich §7.1 privacy argument).
 *
 * Variant / mode / numCandidates / budget are bound so a prover cannot
 * silently switch ballot shapes between the claimed and verified
 * parameters.
 */
export function seedBallotTranscript(
  electionId: Uint8Array,
  mpk: G2Point,
  vk: G1Point,
  ciphertexts: readonly Ciphertext[],
  params: BallotVerifyParams,
): Transcript {
  const t = new Transcript(BALLOT_PROOF_TRANSCRIPT_LABEL);
  t.append('electionId', electionId);
  t.appendPoint('mpk', mpk);
  t.appendPoint('vk', vk);
  t.append('variant', new Uint8Array([params.variant === 'A' ? 0x41 : 0x42]));
  t.append('mode', new Uint8Array([params.mode === 'exact' ? 0x00 : 0x01]));
  t.append('numCandidates', u16BE(params.numCandidates));
  t.append('budget', u16BE(params.budget));
  if (params.variant === 'B') {
    if (params.d === undefined) {
      throw new Error('seedBallotTranscript: Variant B requires params.d');
    }
    t.append('d', u16BE(params.d));
  }
  t.append('|cts|', u16BE(ciphertexts.length));
  for (let i = 0; i < ciphertexts.length; i++) {
    t.appendPoint(`ct.c1[${i}]`, ciphertexts[i]!.c1);
    t.appendPoint(`ct.c2[${i}]`, ciphertexts[i]!.c2);
  }
  return t;
}

/** Candidate set used by a Variant A range proof for a given budget. */
export function rangeCandidates(budget: number): bigint[] {
  const out: bigint[] = new Array(budget + 1);
  for (let i = 0; i <= budget; i++) out[i] = BigInt(i);
  return out;
}

// ---------- verifyBallot ----------

export function verifyBallot(
  inputs: BallotInputs,
  params: BallotVerifyParams,
  mpk: G2Point,
  /** Compressed G₁ public key of the eligibility issuer, 48 bytes. */
  eligibilityKey: Uint8Array,
): VerifyResult {
  // Parameter validation. The codec serialises ℓ and B as u16BE, so 0xFFFF
  // is the natural hard ceiling. Anything larger could not round-trip the
  // wire anyway; bounding here turns oversized params into a clean
  // VerifyResult instead of an allocation blow-up on rangeCandidates()/
  // ciphertext loops.
  if (!Number.isInteger(params.numCandidates)) {
    return { ok: false, reason: 'numCandidates must be an integer' };
  }
  if (params.numCandidates < 1 || params.numCandidates > 0xffff) {
    return { ok: false, reason: `numCandidates (${params.numCandidates}) out of range [1, 65535]` };
  }
  if (!Number.isInteger(params.budget)) {
    return { ok: false, reason: 'budget must be an integer' };
  }
  // Munich spec requires B ≥ 1; "budget 0" would collapse the ballot to
  // all-zero votes and reduce the budget proof to proving a tautology.
  if (params.budget < 1 || params.budget > 0xffff) {
    return { ok: false, reason: `budget (${params.budget}) out of range [1, 65535]` };
  }
  if (params.mode !== 'exact' && params.mode !== 'atMost') {
    return { ok: false, reason: `unknown mode: ${params.mode}` };
  }
  if (params.variant !== 'A' && params.variant !== 'B') {
    return { ok: false, reason: `unknown variant: ${params.variant}` };
  }
  if (params.variant === 'B') {
    if (params.d === undefined || !Number.isInteger(params.d) || params.d <= 0) {
      return { ok: false, reason: 'Variant B requires a positive integer d' };
    }
    // Spec: d = ⌈log₂(B+1)⌉ (Potential Extensions §binary decomposition).
    // Enforce exactly — accepting d > ⌈log₂(B+1)⌉ would silently admit
    // padded bit-decompositions with proof-size attack surface for no
    // cryptographic gain.
    const expectedD = Math.ceil(Math.log2(params.budget + 1));
    if (params.d !== expectedD) {
      return {
        ok: false,
        reason: `Variant B d (${params.d}) must equal ⌈log₂(B+1)⌉ = ${expectedD}`,
      };
    }
  }
  if (inputs.electionId.length !== 32) {
    return { ok: false, reason: `electionId must be 32 bytes (got ${inputs.electionId.length})` };
  }
  if (inputs.pseudonym.length !== 32) {
    return { ok: false, reason: `pseudonym must be 32 bytes (got ${inputs.pseudonym.length})` };
  }
  if (mpk.isIdentity()) {
    return { ok: false, reason: 'mpk is the identity — rejected (would collapse ciphertext privacy)' };
  }
  const expectedCts =
    params.variant === 'A'
      ? params.numCandidates
      : params.numCandidates * (params.d ?? 0);
  if (inputs.ciphertexts.length !== expectedCts) {
    return {
      ok: false,
      reason: `ciphertexts.length (${inputs.ciphertexts.length}) != expected (${expectedCts})`,
    };
  }

  // Track every G1/G2 point we allocate so they are freed in the finally block
  // regardless of which path (ok or early-return) this function takes.
  // Callers own mpk — we do NOT free it here.
  const ownedG1: G1Point[] = [];
  const ownedG2: G2Point[] = [];

  function trackG1(p: G1Point): G1Point { ownedG1.push(p); return p; }
  function trackG2(p: G2Point): G2Point { ownedG2.push(p); return p; }
  function freeOwned(): void {
    for (const p of ownedG1) p.destroyWasm();
    for (const p of ownedG2) p.destroyWasm();
    ownedG1.length = 0;
    ownedG2.length = 0;
  }

  try {
    // Decode vk (subgroup-checked in G1Point.fromBytes).
    let vk: G1Point;
    try {
      vk = trackG1(G1Point.fromBytes(inputs.vk));
    } catch (e) {
      return { ok: false, reason: `vk decode: ${(e as Error).message}` };
    }
    if (vk.isIdentity()) {
      return { ok: false, reason: 'vk is the identity — rejected (sk=0 breaks signature soundness)' };
    }

    // Decode every (C1, C2). Each G2Point.fromBytes runs a subgroup check.
    const cts: Ciphertext[] = new Array(inputs.ciphertexts.length);
    for (let i = 0; i < inputs.ciphertexts.length; i++) {
      const [c1Bytes, c2Bytes] = inputs.ciphertexts[i]!;
      try {
        cts[i] = {
          c1: trackG2(G2Point.fromBytes(c1Bytes)),
          c2: trackG2(G2Point.fromBytes(c2Bytes)),
        };
      } catch (e) {
        return { ok: false, reason: `ciphertext[${i}] decode: ${(e as Error).message}` };
      }
    }

    // Eligibility credential. Verified here rather than by a caller-supplied
    // predicate: the v1 hook was opaque enough that one consumer wired a constant
    // `true` to it, which is a check that exists on paper and nowhere else.
    if (!verifyAttestation(eligibilityKey, inputs.attestation, {
      electionId: inputs.electionId,
    })) {
      return { ok: false, reason: 'attestation verification failed' };
    }
    // The credential must name *this* voter's ballot key. Without this a valid
    // credential issued for another `vk` could be presented with this ballot: the
    // signature would cover it, and it would still be a credential the issuer signed.
    if (!bytesEqual(inputs.attestation.vk, inputs.vk)) {
      return { ok: false, reason: 'attestation vk does not match the ballot vk' };
    }
    if (!bytesEqual(inputs.attestation.pseudonym, inputs.pseudonym)) {
      return { ok: false, reason: 'attestation pseudonym does not match the ballot' };
    }

    // Decode zkProof.
    let bvp: BallotValidityProof;
    try {
      bvp = decodeBallotValidityProof(inputs.zkProof, {
        variant: params.variant,
        numCandidates: params.numCandidates,
        budget: params.budget,
        d: params.d,
      });
    } catch (e) {
      return { ok: false, reason: `zkProof decode: ${(e as Error).message}` };
    }
    // Track all G2 commitment points decoded from the proof (a1, a2 per branch).
    for (const orProof of bvp.rangeOrBit) {
      for (const br of orProof.branches) {
        trackG2(br.a1);
        trackG2(br.a2);
      }
    }
    if (bvp.budget.mode === 'atMost') {
      for (const br of bvp.budget.proof.branches) {
        trackG2(br.a1);
        trackG2(br.a2);
      }
    }

    if (bvp.budget.mode !== params.mode) {
      return {
        ok: false,
        reason: `budget mode on wire (${bvp.budget.mode}) differs from params (${params.mode})`,
      };
    }

    // Build the shared transcript and run every proof against it.
    const t = seedBallotTranscript(inputs.electionId, mpk, vk, cts, params);

    let ctSum: Ciphertext;
    if (params.variant === 'A') {
      if (bvp.rangeOrBit.length !== params.numCandidates) {
        return {
          ok: false,
          reason: `rangeOrBit.length (${bvp.rangeOrBit.length}) != numCandidates (${params.numCandidates})`,
        };
      }
      const candidates = rangeCandidates(params.budget);
      for (let j = 0; j < params.numCandidates; j++) {
        t.append('ballot:range', u16BE(j));
        const stmt: ORStatement = { ct: cts[j]!, mpk, candidates };
        if (!verifyOR(stmt, bvp.rangeOrBit[j]!, t)) {
          return { ok: false, reason: `range proof ${j} failed` };
        }
      }
      if (cts.length === 1) {
        ctSum = cts[0]!;
      } else {
        ctSum = sumCts(cts);
        // sumCts returns a fresh allocation — track it so it gets freed.
        trackG2(ctSum.c1);
        trackG2(ctSum.c2);
      }
    } else {
      const d = params.d!;
      const totalBits = params.numCandidates * d;
      if (bvp.rangeOrBit.length !== totalBits) {
        return {
          ok: false,
          reason: `rangeOrBit.length (${bvp.rangeOrBit.length}) != numCandidates·d (${totalBits})`,
        };
      }
      const bitCandidates: readonly bigint[] = [0n, 1n];
      for (let jk = 0; jk < totalBits; jk++) {
        t.append('ballot:bit', u16BE(jk));
        const stmt: ORStatement = { ct: cts[jk]!, mpk, candidates: bitCandidates };
        if (!verifyOR(stmt, bvp.rangeOrBit[jk]!, t)) {
          return { ok: false, reason: `bit proof ${jk} failed` };
        }
      }
      // Reconstruct each ĉ_j, then ĉ = Σ_j ĉ_j.
      const cHats: Ciphertext[] = new Array(params.numCandidates);
      for (let j = 0; j < params.numCandidates; j++) {
        let acc: Ciphertext | null = null;
        for (let k = 0; k < d; k++) {
          const weighted = scalarMulCt(1n << BigInt(k), cts[j * d + k]!);
          trackG2(weighted.c1);
          trackG2(weighted.c2);
          if (acc === null) {
            acc = weighted;
          } else {
            const next = addCt(acc, weighted);
            trackG2(next.c1);
            trackG2(next.c2);
            acc = next;
          }
        }
        cHats[j] = acc!;
      }
      if (cHats.length === 1) {
        ctSum = cHats[0]!;
      } else {
        ctSum = sumCts(cHats);
        trackG2(ctSum.c1);
        trackG2(ctSum.c2);
      }
    }

    t.append('ballot:budget', new Uint8Array([0]));
    if (
      !verifyBudget(
        { ctSum, mpk, budget: BigInt(params.budget) },
        bvp.budget,
        t,
      )
    ) {
      return { ok: false, reason: 'budget proof failed' };
    }

    // Schnorr — canonical preimage → keccak256 → verify.
    let sig;
    try {
      sig = decodeSchnorr(inputs.voterSignature);
    } catch (e) {
      return { ok: false, reason: `signature decode: ${(e as Error).message}` };
    }
    trackG1(sig.R); // R is a G1Point allocated by decodeSchnorr

    const preimage = canonicalBallotMessage({
      electionId: inputs.electionId,
      pseudonym: inputs.pseudonym,
      ciphertexts: inputs.ciphertexts,
      zkProof: inputs.zkProof,
      attestation: inputs.attestation,
    });
    const msg = keccak256(preimage, 'bytes');
    if (!schnorrVerify(vk, msg, sig)) {
      // Name a format mismatch as one. A signature made over the v1 message does not
      // fail informatively against v2 — `schnorrVerify` just returns false, which
      // reads as "wrong voter" and sends the reader after the key. Checking the v1
      // preimage here costs one keccak on a path that has already failed.
      if (schnorrVerify(vk, keccak256(preV1BallotMessage(inputs), 'bytes'), sig)) {
        return {
          ok: false,
          reason:
            'voter signature is over the pre-attestation ballot format ' +
            '(SHUTTER-VOTE-BALLOT-v1); this ballot was built by an older client',
        };
      }
      return { ok: false, reason: 'signature invalid' };
    }

    return { ok: true };
  } finally {
    freeOwned();
  }
}

function u16BE(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new Error(`u16 out of range: ${n}`);
  const out = new Uint8Array(2);
  out[0] = (n >>> 8) & 0xff;
  out[1] = n & 0xff;
  return out;
}
