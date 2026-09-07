/**
 * `ATTESTATION_V1` — minting, verification, and the cross-implementation digest.
 *
 * These credentials are an interop contract: one side mints, another verifies,
 * and the two are usually different languages and different processes. Nothing
 * detects a framing mismatch at runtime — a wrong length prefix or field order
 * produces credentials that simply fail to verify everywhere, which surfaces as
 * an election where no ballot is admitted rather than as an error.
 *
 * So the digest is pinned two ways: a self-consistent round trip (mint → verify,
 * plus every tampering that must fail), and a **known-answer test** against a
 * credential produced by the Python implementation. The second is the one that
 * would catch a transcript change here; the first alone would happily agree with
 * itself.
 */

import {
  Attestation,
  attestationMessage,
  initCurves,
  signAttestation,
  verifyAttestation,
  verifyAttestationSig,
} from '../src';
import { schnorrKeygen } from '../src/voting/schnorr';

beforeAll(async () => {
  await initCurves();
});

// Pinned so signatures are reproducible run to run.
const ELIGIBILITY_SK =
  0x2f1a4c8e9b3d7f0a5e6c1d8b4a9f3e2c7d0b6a5948372615f4e3d2c1b0a99887n;
const NONCE_K =
  0x0b7e15162398d3f4a1c9e2705f8b6d4c3a291807f6e5d4c3b2a1908f7e6d5c4bn;

function bytes(fill: number, len: number): Uint8Array {
  return new Uint8Array(len).fill(fill);
}

function unhex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/** A voter vk must be a real G1 point, not arbitrary bytes. */
function someVk(seed: bigint): Uint8Array {
  const { vk } = schnorrKeygen(seed);
  try {
    return vk.toBytes();
  } finally {
    vk.destroyWasm();
  }
}

describe('ATTESTATION_V1', () => {
  const eligibility = () => schnorrKeygen(ELIGIBILITY_SK);

  const base = () => ({
    electionId: bytes(0x11, 32),
    pseudonym: bytes(0x22, 32),
    vk: someVk(0x1234n),
    weight: 5n,
    nonce: 1n,
  });

  it('a minted credential verifies under the issuer key', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      expect(signature.length).toBe(80);
      const ok = verifyAttestation(
        eligVk.toBytes(),
        { ...fields, signature },
        { electionId: fields.electionId },
      );
      expect(ok).toBe(true);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('is deterministic given a pinned nonce', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const a = signAttestation(sk, eligVk, base(), NONCE_K);
      const b = signAttestation(sk, eligVk, base(), NONCE_K);
      expect(Buffer.from(a).toString('hex')).toBe(
        Buffer.from(b).toString('hex'),
      );
    } finally {
      eligVk.destroyWasm();
    }
  });

  // Every field the credential binds. A signature that survives any of these
  // would mean the field is not actually covered by the transcript.
  it.each([
    ['weight', (a: Attestation) => ({ ...a, weight: a.weight + 1n })],
    ['nonce', (a: Attestation) => ({ ...a, nonce: a.nonce + 1n })],
    ['electionId', (a: Attestation) => ({ ...a, electionId: bytes(0x33, 32) })],
    ['pseudonym', (a: Attestation) => ({ ...a, pseudonym: bytes(0x44, 32) })],
    ['vk', (a: Attestation) => ({ ...a, vk: someVk(0x5678n) })],
  ])('rejects a credential with a tampered %s', (_label, tamper) => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      const tampered = tamper({ ...fields, signature });
      expect(verifyAttestationSig(eligVk.toBytes(), tampered)).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  // The inverse of what this asserted while voting power was clamped: there is no
  // upper bound on weight any more, matching geg. The bound had to be at least the
  // largest legitimate holder to be usable, i.e. effectively the whole supply, at
  // which point an issuer able to forge one weight could already forge a decisive
  // one. Keeping the tally computable is the scale factor's job now.
  it('accepts an arbitrarily large weight — there is no ceiling', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      for (const weight of [50n, 10n ** 12n, (1n << 200n) - 1n]) {
        const fields = { ...base(), weight };
        const signature = signAttestation(sk, eligVk, fields, NONCE_K);
        expect(
          verifyAttestation(
            eligVk.toBytes(),
            { ...fields, signature },
            { electionId: fields.electionId },
          ),
        ).toBe(true);
      }
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('still rejects weight below 1', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = { ...base(), weight: 1n };
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      expect(
        verifyAttestation(
          eligVk.toBytes(),
          { ...fields, signature, weight: 0n },
          { electionId: fields.electionId },
        ),
      ).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('rejects a credential bound to a different election than expected', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      expect(
        verifyAttestation(
          eligVk.toBytes(),
          { ...fields, signature },
          { electionId: bytes(0x99, 32) },
        ),
      ).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('refuses to mint out-of-range weight or nonce', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      expect(() =>
        signAttestation(sk, eligVk, { ...base(), weight: 0n }, NONCE_K),
      ).toThrow(/weight must be >= 1/);
      expect(() =>
        signAttestation(sk, eligVk, { ...base(), nonce: 0n }, NONCE_K),
      ).toThrow(/nonce must be >= 1/);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('rejects malformed field sizes', () => {
    expect(() =>
      attestationMessage(bytes(1, 31), bytes(2, 32), someVk(1n), 1n, 1n),
    ).toThrow(/electionId must be 32 bytes/);
    expect(() =>
      attestationMessage(bytes(1, 32), bytes(2, 33), someVk(1n), 1n, 1n),
    ).toThrow(/pseudonym must be 32 bytes/);
    expect(() =>
      attestationMessage(bytes(1, 32), bytes(2, 32), bytes(3, 47), 1n, 1n),
    ).toThrow(/vk must be 48 bytes/);
  });

  /**
   * Known-answer test — the credential below was minted by the Python
   * implementation (`geg.crypto.attestation.sign_attestation`) and is carried in
   * its conformance corpus as `attestation/attestation_v1_valid.json`.
   *
   * A Schnorr signature is bound to its exact message, so this passing means the
   * transcript built here is byte-identical to the one built there. If it fails,
   * the two implementations have diverged and no credential minted by either
   * will be accepted by the other — do not "fix" it by editing these bytes.
   */
  it('accepts a credential minted by the Python implementation', () => {
    const vector = {
      eligibilityKey:
        '972a59075fca0729b40b2cea5bb9685afdd219e77407e13631664c53b847cdca' +
        'd45ab174a073aaa4122ad813fa094485',
      electionId:
        '1111111111111111111111111111111111111111111111111111111111111111',
      pseudonym:
        '2222222222222222222222222222222222222222222222222222222222222222',
      vk:
        '8f3ad24f4f7d9132f2a148f3a57dcc2ca12e354d5c4bdd6c93aa8625c4904dbe' +
        '962a0ae167dea3414488876c7c2645a1',
      weight: 5n,
      nonce: 1n,
      signature:
        '90f40c1d2b7319ea5440eb0c3250b8db9db64270aa9841f8ce2556a7c786dc96' +
        '6e8d5f300848f4917aa88bf941882d4e09e6c30436dd0aee41a2607e2278e371' +
        '74799b1ceb0f10c8f00f4a667ef66e82',
    };

    const attestation: Attestation = {
      electionId: unhex(vector.electionId),
      pseudonym: unhex(vector.pseudonym),
      vk: unhex(vector.vk),
      weight: vector.weight,
      nonce: vector.nonce,
      signature: unhex(vector.signature),
    };

    expect(
      verifyAttestation(unhex(vector.eligibilityKey), attestation, {
        electionId: attestation.electionId,
      }),
    ).toBe(true);
  });
});
