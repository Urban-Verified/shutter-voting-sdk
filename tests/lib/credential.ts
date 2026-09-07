/**
 * Mint an eligibility credential for a test ballot.
 *
 * From v2 every ballot carries one and the voter's signature covers it, so any test
 * that builds or verifies a ballot needs an issuer. This keeps that setup in one place
 * rather than in each suite, and — more usefully — keeps the issuer key *out* of the
 * ballot fixtures, so a test cannot accidentally assert against a credential minted
 * under a key the verifier does not hold.
 */

import { G1Point } from '../../src/crypto/curve';
import { schnorrKeygen } from '../../src/voting/schnorr';
import { signAttestation, type Attestation } from '../../src/voting/attestation';

export interface TestIssuer {
  /** The issuer's public key, as `verifyBallot` takes it (48-byte compressed G₁). */
  eligibilityKey: Uint8Array;
  /** Mint a credential for this voter. Caller owns nothing; bytes only. */
  mint(args: {
    electionId: Uint8Array;
    pseudonym: Uint8Array;
    vk: Uint8Array;
    weight?: bigint;
    nonce?: bigint;
  }): Attestation;
  /** Frees the issuer's WASM key. Call in `afterAll`. */
  destroy(): void;
}

/**
 * A fresh issuer. `seed` is unused beyond documenting intent at the call site —
 * `schnorrKeygen` draws its own randomness, and no test here depends on the issuer key
 * being reproducible (the credential's own signature is what gets pinned, via an
 * explicit `k`, where reproducibility is actually needed).
 */
export function testIssuer(): TestIssuer {
  const { sk, vk } = schnorrKeygen();
  return {
    eligibilityKey: vk.toBytes(),
    mint({ electionId, pseudonym, vk: voterVk, weight = 1n, nonce = 1n }) {
      const fields = { electionId, pseudonym, vk: voterVk, weight, nonce };
      return { ...fields, signature: signAttestation(sk, vk, fields) };
    },
    destroy() {
      vk.destroyWasm();
    },
  };
}

/** A credential that no issuer signed — for the rejection paths. */
export function forgedCredential(args: {
  electionId: Uint8Array;
  pseudonym: Uint8Array;
  vk: Uint8Array;
  weight?: bigint;
  nonce?: bigint;
}): Attestation {
  return {
    electionId: args.electionId,
    pseudonym: args.pseudonym,
    vk: args.vk,
    weight: args.weight ?? 1n,
    nonce: args.nonce ?? 1n,
    signature: new Uint8Array(80),
  };
}

/** Re-export so suites need one import for the whole credential story. */
export { G1Point };
