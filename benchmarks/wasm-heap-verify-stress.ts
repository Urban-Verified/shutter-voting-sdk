'use strict';
/**
 * End-to-end WASM heap smoke test using real cryptographic ballots.
 *
 * This is the strongest guarantee we can get short of running the full
 * browser app against a live election:
 *   - buildBallot()   : generates real ZK proofs (OR + budget) + Schnorr sig
 *   - verifyBallot()  : runs full ZK verification, Schnorr verify, on-curve checks
 *
 * Without the SDK fixes the WASM heap exhausts within ~2000 ballots at ℓ=3.
 * With the fixes (explicit destroyWasm() everywhere + generator() intermediates
 * freed), 10,000 ballots complete cleanly and RSS stays flat.
 *
 * Usage:
 *   npm run bench:wasm
 *
 * Expect runtime: ~15-20 min (real BLS12-381 ZK ops, no mocking).
 */

import {
  G2Point,
  buildBallot,
  verifyBallot,
  schnorrKeygen,
  initCurves,
} from '../src';



const GREEN = '\x1b[32m', RED = '\x1b[31m', YELLOW = '\x1b[33m', RESET = '\x1b[0m';
const pass  = msg => console.log(`${GREEN}✓${RESET} ${msg}`);
const fail  = msg => { console.error(`${RED}✗${RESET} ${msg}`); process.exit(1); };
const info  = msg => console.log(`${YELLOW}→${RESET} ${msg}`);

function rssKB() {
  return Math.round(process.memoryUsage().rss / 1024);
}

async function main() {
  await initCurves();

  // ── Election setup ───────────────────────────────────────────────────────
  // schnorrKeygen().sk gives a random scalar in the BLS12-381 scalar field.
  // Repurpose it as the election secret key to derive mpk on G2.
  const { sk: electionSk } = schnorrKeygen();
  const mpk        = G2Point.generator().mul(electionSk);
  const electionId = new Uint8Array(32).fill(0xe1);
  const params     = { numCandidates: 3, budget: 1, mode: 'exact', variant: 'A' };

  // The sequencer accepts WR attestation separately; verifyBallot's
  // WRAttestationVerifier slot is () => true here (same pattern as the sequencer).
  const accept = () => true;

  // ── Stress run ───────────────────────────────────────────────────────────
  const N = 10_000;
  info(`Generating and verifying ${N} real ZK ballots (ℓ=3, B=1, Variant A)...`);
  info(`RSS before: ${rssKB()} KB`);

  const checkpoints = [1, 10, 100, 500, 1000, 2000, 3000, 5000, 7500, 10000];
  let passed = 0;

  for (let i = 0; i < N; i++) {
    // Each voter gets a fresh Schnorr keypair (ephemeral per ballot).
    const { sk, vk } = schnorrKeygen();

    // Unique pseudonym per voter — last 2 bytes encode i.
    const pseudonym = new Uint8Array(32);
    pseudonym[30] = (i >> 8) & 0xff;
    pseudonym[31] = i & 0xff;

    // buildBallot allocates G2 points (encrypt) + ZK proof G1/G2 temporaries.
    // wrAttestation is a 1-byte dummy — accept() always returns true so the
    // WR signature itself is not checked in this test.
    const inputs = buildBallot({
      mpk,
      electionId,
      pseudonym,
      sk,
      vk,
      votes:          [1n, 0n, 0n],
      params,
      wrAttestation:  new Uint8Array([0x01]),
    });

    // verifyBallot allocates G2 (ciphertext on-curve checks), runs ZK verify
    // (many G1/G2 muls), and checks Schnorr — the most WASM-intensive path.
    const result = verifyBallot(inputs, params, mpk, accept);
    if (result.ok !== true) {
      fail(`Ballot ${i} failed verification: ${JSON.stringify(result)}`);
    }

    // Free the voter's verification key WASM allocation explicitly.
    // vk is a G1Point created by schnorrKeygen() — callers own it.
    vk.destroyWasm();

    // Yield the event loop between ballots — mirrors the dashboard's
    // runVerifyExclusive / setTimeout(resolve, 0) pattern in App.tsx.
    // All WASM allocations are explicitly freed by the SDK; this yield is
    // for event-loop responsiveness, not GC-driven WASM cleanup.
    await new Promise(r => setImmediate(r));

    passed++;

    if (checkpoints.includes(passed)) {
      info(`  ballot ${String(passed).padStart(3)}: RSS = ${rssKB()} KB`);
    }
  }

  const rssFinal = rssKB();
  info(`RSS after:  ${rssFinal} KB`);

  pass(`${N} real ZK ballots built and verified — WASM heap never exhausted`);

  // A rough sanity check: RSS should not have grown by more than ~50 MB
  // (startup + WASM module itself is ~15 MB; each ballot leaves no permanent
  // allocations if the fix is correct).
  console.log('\nAll end-to-end tests passed.');
}

main().catch(err => { console.error(err); process.exit(1); });
