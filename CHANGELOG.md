# Changelog

## 0.3.0 — BREAKING

The eligibility credential moves **inside the signed ballot**. One voter signature now covers
the ballot and the credential together, so the separate binding signature consumers had to
build themselves is no longer needed.

### Why

`BallotInputs.wrAttestation` was an opaque blob checked by a caller-supplied closure, and it
was not part of `canonicalBallotMessage`. It could not express `weight` or `nonce`, and
nothing the voter signed committed to them. Consumers worked around this identically: pass an
empty placeholder, carry the real credential beside the ballot, and add a **second** Schnorr
signature over a separate transcript to bind the two — because otherwise whoever paired a
ballot with a credential chose the voter's weight, and `nonce` orders their re-votes.

That binding transcript ended up implemented four times across two languages, all of which
had to agree byte-for-byte. Folding the credential into the ballot deletes all of them.

### Breaking changes

| Removed | Replacement |
| --- | --- |
| `BallotInputs.wrAttestation: Uint8Array` | `BallotInputs.attestation: Attestation` |
| `WRAttestationVerifier`, and `verifyBallot`'s 4th parameter | `verifyBallot(..., eligibilityKey: Uint8Array)` — the SDK verifies the credential itself |
| `buildBallot({ …, wrAttestation })` | `buildBallot({ …, attestation })` |
| `AttestationScheme`, `ATTESTATION_LEGACY`, `legacyAttestationMessage` | none — stay on **0.1.2** if you need the weightless legacy scheme |
| `verifyAttestation(key, a, { electionId, maxWeight })` | `verifyAttestation(key, a, { electionId })` |

`canonicalBallotMessage` takes an `attestation` and its domain separator moves to
`SHUTTER-VOTE-BALLOT-v2`. **Ballots signed by 0.2.0 or earlier do not verify under 0.3.0.**
`verifyBallot` detects that case specifically and reports *"voter signature is over the
pre-attestation ballot format"* rather than a generic invalid signature, so a version skew
does not read as a wrong key.

### Migration

```diff
+ const credential = await requestEligibilityCredential(...);   // before building

  const ballot = buildBallot({
    mpk, electionId, pseudonym, sk, vk, votes, params,
-   wrAttestation: new Uint8Array(0),
+   attestation: credential,
  });

- const r = verifyBallot(inputs, params, mpk, myWrVerifier);
+ const r = verifyBallot(inputs, params, mpk, eligibilityPublicKey);
```

Then **delete your binding layer** — the second signature, its transcript, and its vectors.
The voter's ballot signature does that job now.

Order matters: the credential must exist *before* `buildBallot`, because the signature covers
it. Code that minted the credential after building the ballot has to be reordered.

### Notes

- **The whole credential is covered, signature bytes included.** Schnorr signing is
  randomised, so one set of credential fields has many valid signatures; covering only the
  fields would let a relay swap one for another and keep the voter's signature valid. Harmless
  semantically, but it would make the envelope malleable — and published ballots are
  re-aggregated byte-for-byte by auditors, with ballot digests used as stable identifiers.
- **Weight is uncapped.** `verifyAttestation` no longer takes `maxWeight`. The bound had to be
  at least the largest legitimate holder to be usable, at which point an issuer able to forge
  one weight could already forge a decisive one.
- **The proof transcript did not change.** Its domain separator is now
  `SHUTTER-VOTE-BALLOT-PROOF-v1`, deliberately distinct from the message label so that
  versioning the message never re-challenges every proof. Proof bytes are unaffected by this
  release beyond that rename.
- **Coarser rejection reasons.** With one signature, a tampered ciphertext and a swapped
  credential both surface as an invalid signature. The previous two-step check could tell them
  apart.

## 0.2.0

Weighted tally support and `ATTESTATION_V1`.

## 0.1.2

Last release with the weightless `ATTESTATION_LEGACY` scheme and the opaque
`wrAttestation` slot.
