import { G1Point, Q, initCurves, modQ, randomScalar } from '../src';
import {
  schnorrKeygen,
  schnorrSign,
  schnorrVerify,
} from '../src/voting/schnorr';

beforeAll(async () => {
  await initCurves();
});

describe('Schnorr', () => {
  it('keygen produces vk = sk · P₁', () => {
    const { sk, vk } = schnorrKeygen();
    expect(vk.equals(G1Point.generator().mul(sk))).toBe(true);
  });

  it('keygen accepts injected sk and normalises into [0, Q)', () => {
    const raw = randomScalar();
    const { sk, vk } = schnorrKeygen(raw);
    expect(sk).toBe(modQ(raw));
    expect(vk.equals(G1Point.generator().mul(raw))).toBe(true);
  });

  it('sign / verify round-trip', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('hello ballot');
    const sig = schnorrSign(sk, vk, msg);
    expect(schnorrVerify(vk, msg, sig)).toBe(true);
  });

  it('fresh signatures differ even for the same (sk, msg) — k is random', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('same msg');
    const a = schnorrSign(sk, vk, msg);
    const b = schnorrSign(sk, vk, msg);
    expect(a.R.equals(b.R)).toBe(false);
    expect(a.s).not.toBe(b.s);
    expect(schnorrVerify(vk, msg, a)).toBe(true);
    expect(schnorrVerify(vk, msg, b)).toBe(true);
  });

  it('sign with injected k is deterministic', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('pinned');
    const k = 0xabadcafen;
    const a = schnorrSign(sk, vk, msg, k);
    const b = schnorrSign(sk, vk, msg, k);
    expect(a.R.equals(b.R)).toBe(true);
    expect(a.s).toBe(b.s);
    expect(schnorrVerify(vk, msg, a)).toBe(true);
  });

  it('verification rejects a message tampered after signing', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('original');
    const sig = schnorrSign(sk, vk, msg);
    const tampered = new TextEncoder().encode('tampered');
    expect(schnorrVerify(vk, tampered, sig)).toBe(false);
  });

  it('verification rejects a signature under the wrong key', () => {
    const alice = schnorrKeygen();
    const mallory = schnorrKeygen();
    const msg = new TextEncoder().encode('m');
    const sig = schnorrSign(alice.sk, alice.vk, msg);
    expect(schnorrVerify(mallory.vk, msg, sig)).toBe(false);
  });

  it('tampered R or s breaks verification', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('x');
    const sig = schnorrSign(sk, vk, msg);

    const badR = { R: sig.R.add(G1Point.generator()), s: sig.s };
    expect(schnorrVerify(vk, msg, badR)).toBe(false);

    const badS = { R: sig.R, s: modQ(sig.s + 1n) };
    expect(schnorrVerify(vk, msg, badS)).toBe(false);
  });

  it('identical sk + msg across two sessions — both signatures verify, neither equals the other', () => {
    // Reinforces that Schnorr is not a deterministic scheme here; replays
    // caught by the ballot-level nym / nonce layer, not the signature itself.
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('repeatable');
    const first = schnorrSign(sk, vk, msg);
    const second = schnorrSign(sk, vk, msg);
    expect(schnorrVerify(vk, msg, first)).toBe(true);
    expect(schnorrVerify(vk, msg, second)).toBe(true);
    expect(first.R.equals(second.R)).toBe(false);
  });

  it('s lies in [0, Q) regardless of challenge magnitude', () => {
    const { sk, vk } = schnorrKeygen();
    const msg = new TextEncoder().encode('bound check');
    for (let i = 0; i < 4; i++) {
      const sig = schnorrSign(sk, vk, msg);
      expect(sig.s).toBeGreaterThanOrEqual(0n);
      expect(sig.s).toBeLessThan(Q);
    }
  });
});
