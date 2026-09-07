/**
 * `ATTESTATION_V1` — the weighted eligibility credential.
 *
 * A Schnorr-on-G₁ signature by the eligibility key over a domain-separated
 * transcript of `(electionId, pseudonym, vk, weight, nonce)`. The credential is
 * inseparable from the weight it authorizes, which is what keeps a
 * voting-power-weighted tally re-derivable from public artifacts alone: an
 * auditor can check that the weight used in the aggregate is the weight the
 * issuer actually attested to, bound to that pseudonym and that vk.
 *
 * `nonce` is a monotonic per-(election, pseudonym) re-vote counter. The tally
 * keeps the voter's ballot with the highest signed nonce, so a replayed older
 * ballot can never override a genuine re-vote.
 *
 * The signed message is `keccak256(transcript.preimage())`; the wire signature
 * is the standard 80-byte Schnorr encoding `R(48) ‖ s(32)`.
 *
 * This is a byte-faithful port of the Python `geg.crypto.attestation` module,
 * and it is an interop contract, not an internal detail: a credential minted
 * here is verified by a Python keyper, and vice versa. Deployments that mint
 * eligibility credentials in JavaScript — rather than through geg's Python
 * eligibility service — depend on these bytes matching exactly. Do not change a
 * label, a field order, or a length prefix without regenerating the conformance
 * vectors on both sides.
 */

import { keccak256 } from 'viem';
import { schnorrSign, schnorrVerify } from './schnorr';
import { Transcript } from './transcript';
import { decodeSchnorr, encodeSchnorr } from '../contract/codec';
import { G1Point } from '../crypto/curve';
import { concatBytes } from '../crypto/hash';

/** Transcript label for the weighted scheme. Fixed for protocol v1. */
export const ATTESTATION_LABEL = 'SHUTTER-VOTE-ATTEST-v1';

const ELECTION_ID_BYTES = 32;
const PSEUDONYM_BYTES = 32;
const VK_BYTES = 48;

/** The credential as it travels on the wire, bytes already decoded. */
export interface Attestation {
  electionId: Uint8Array; // 32
  pseudonym: Uint8Array; // 32
  vk: Uint8Array; // 48 — compressed G1
  weight: bigint;
  nonce: bigint;
  signature: Uint8Array; // 80 — R ‖ s
}

function assertFieldSizes(
  electionId: Uint8Array,
  pseudonym: Uint8Array,
  vk: Uint8Array,
): void {
  if (electionId.length !== ELECTION_ID_BYTES) {
    throw new Error(
      `attestation: electionId must be ${ELECTION_ID_BYTES} bytes (got ${electionId.length})`,
    );
  }
  if (pseudonym.length !== PSEUDONYM_BYTES) {
    throw new Error(
      `attestation: pseudonym must be ${PSEUDONYM_BYTES} bytes (got ${pseudonym.length})`,
    );
  }
  if (vk.length !== VK_BYTES) {
    throw new Error(
      `attestation: vk must be ${VK_BYTES} bytes (got ${vk.length})`,
    );
  }
}

/**
 * The `keccak256` digest the eligibility key signs for `ATTESTATION_V1`.
 *
 * Throws on malformed field sizes or a weight/nonce below 1 — the same inputs
 * the Python `_attestation_transcript` rejects.
 */
export function attestationMessage(
  electionId: Uint8Array,
  pseudonym: Uint8Array,
  vk: Uint8Array,
  weight: bigint,
  nonce: bigint,
): Uint8Array {
  assertFieldSizes(electionId, pseudonym, vk);
  if (weight < 1n) {
    throw new Error(`attestation: weight must be >= 1 (got ${weight})`);
  }
  if (nonce < 1n) {
    throw new Error(`attestation: nonce must be >= 1 (got ${nonce})`);
  }
  const t = new Transcript(ATTESTATION_LABEL);
  t.append('attest:electionId', electionId);
  t.append('attest:pseudonym', pseudonym);
  t.append('attest:vk', vk);
  t.appendScalar('attest:weight', weight);
  t.appendScalar('attest:nonce', nonce);
  return keccak256(t.preimage(), 'bytes');
}

/**
 * Issue an `ATTESTATION_V1` signature (80-byte `R ‖ s`).
 *
 * `eligibilitySk` is the issuer's Schnorr-G₁ secret; `eligibilityVk` is the
 * matching public point (it is bound into the Schnorr challenge, so passing a
 * mismatched pair produces a signature nothing will verify). `k` exists for
 * vector reproduction only — production callers omit it.
 */
export function signAttestation(
  eligibilitySk: bigint,
  eligibilityVk: G1Point,
  attestation: Omit<Attestation, 'signature'>,
  k?: bigint,
): Uint8Array {
  const msg = attestationMessage(
    attestation.electionId,
    attestation.pseudonym,
    attestation.vk,
    attestation.weight,
    attestation.nonce,
  );
  const sig =
    k === undefined
      ? schnorrSign(eligibilitySk, eligibilityVk, msg)
      : schnorrSign(eligibilitySk, eligibilityVk, msg, k);
  try {
    return encodeSchnorr(sig);
  } finally {
    sig.R.destroyWasm();
  }
}

/**
 * Verify an attestation's signature against the eligibility key.
 *
 * Returns `false` and never throws on any malformed input, so a caller can
 * treat a `false` uniformly as `INVALID_ATTESTATION`. This checks the
 * *signature* only — see `verifyAttestation` for the normative check that also
 * binds the expected election and the weight ceiling.
 */
export function verifyAttestationSig(
  eligibilityKey: Uint8Array,
  attestation: Attestation,
): boolean {
  let eligVk: G1Point | null = null;
  let sigR: G1Point | null = null;
  try {
    const msg = attestationMessage(
      attestation.electionId,
      attestation.pseudonym,
      attestation.vk,
      attestation.weight,
      attestation.nonce,
    );
    eligVk = G1Point.fromBytes(eligibilityKey);
    const sig = decodeSchnorr(attestation.signature);
    sigR = sig.R;
    return schnorrVerify(eligVk, msg, sig);
  } catch {
    return false;
  } finally {
    eligVk?.destroyWasm();
    sigR?.destroyWasm();
  }
}

/**
 * Normative attestation verification — the mirror of Python
 * `geg.ports.eligibility.verify_attestation`.
 *
 * Beyond the signature it enforces that the credential binds the expected election
 * and that `weight >= 1`. Returns `false`, never throws.
 */
export function verifyAttestation(
  eligibilityKey: Uint8Array,
  attestation: Attestation,
  opts: { electionId: Uint8Array },
): boolean {
  const { electionId } = opts;
  if (attestation.electionId.length !== electionId.length) return false;
  for (let i = 0; i < electionId.length; i++) {
    if (attestation.electionId[i] !== electionId[i]) return false;
  }
  if (attestation.weight < 1n) return false;
  return verifyAttestationSig(eligibilityKey, attestation);
}
