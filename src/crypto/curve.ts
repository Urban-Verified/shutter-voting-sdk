/**
 * Typed wrappers over BLST's raw WASM bindings for the two curve points.
 *
 * Scalars are plain `bigint`s — see `field.ts` and the plan §4.1 deviation
 * note. The wrappers survive here because BLST's raw API has two specific
 * footguns we want to enforce away:
 *   1. `fromBytes` always runs `on_curve` + `in_group` before accepting
 *      a compressed point.
 *   2. `add` / `mul` / `neg` dup before mutating, so operations are pure
 *      from the caller's point of view.
 *
 * Serialisation is always the 48 / 96-byte compressed BLS12-381 encoding
 * that the on-chain contract consumes (§2 of the dev plan).
 */

import type { P1 as BlstP1, P2 as BlstP2 } from './blst/types';
import { blst } from './init';
import { SCALAR_BYTES, bigIntToBytesBE, modQ } from './field';

/** Encode a scalar (bigint) as the BLST Scalar object expected by `mult`. */
function blstScalar(s: bigint) {
  const be = bigIntToBytesBE(modQ(s), SCALAR_BYTES);
  const scalar = new (blst().Scalar)();
  scalar.from_bendian(be);
  return scalar;
}

// ---------- G1 (voter verification keys, Schnorr) ----------

export const G1_BYTES = 48;

export class G1Point {
  constructor(readonly inner: BlstP1) {}

  static generator(): G1Point {
    return new G1Point(blst().P1.generator());
  }

  static identity(): G1Point {
    return new G1Point(new (blst().P1)());
  }

  static fromBytes(b: Uint8Array): G1Point {
    if (b.length !== G1_BYTES) {
      throw new Error(`G1Point.fromBytes: expected 48 bytes, got ${b.length}`);
    }
    const p = new (blst().P1)(b);
    if (!p.on_curve()) {
      throw new Error('G1Point.fromBytes: point not on curve');
    }
    if (!p.in_group()) {
      throw new Error('G1Point.fromBytes: point not in prime-order subgroup');
    }
    return new G1Point(p);
  }

  static hashToCurve(msg: Uint8Array, dst: Uint8Array): G1Point {
    const p = new (blst().P1)();
    p.hash_to(msg, new TextDecoder().decode(dst));
    return new G1Point(p);
  }

  toBytes(): Uint8Array {
    return this.inner.compress();
  }

  isIdentity(): boolean {
    return this.inner.is_inf();
  }

  add(o: G1Point): G1Point {
    return new G1Point(this.inner.dup().add(o.inner));
  }

  sub(o: G1Point): G1Point {
    return new G1Point(this.inner.dup().add(o.inner.dup().neg()));
  }

  neg(): G1Point {
    return new G1Point(this.inner.dup().neg());
  }

  mul(s: bigint): G1Point {
    return new G1Point(this.inner.dup().mult(blstScalar(s)));
  }

  equals(o: G1Point): boolean {
    return this.inner.is_equal(o.inner);
  }
}

// ---------- G2 (encryption group; mpk, C1, C2 all live here) ----------

export const G2_BYTES = 96;

export class G2Point {
  constructor(readonly inner: BlstP2) {}

  static generator(): G2Point {
    return new G2Point(blst().P2.generator());
  }

  static identity(): G2Point {
    return new G2Point(new (blst().P2)());
  }

  static fromBytes(b: Uint8Array): G2Point {
    if (b.length !== G2_BYTES) {
      throw new Error(`G2Point.fromBytes: expected 96 bytes, got ${b.length}`);
    }
    const p = new (blst().P2)(b);
    if (!p.on_curve()) {
      throw new Error('G2Point.fromBytes: point not on curve');
    }
    if (!p.in_group()) {
      throw new Error('G2Point.fromBytes: point not in prime-order subgroup');
    }
    return new G2Point(p);
  }

  static hashToCurve(msg: Uint8Array, dst: Uint8Array): G2Point {
    const p = new (blst().P2)();
    p.hash_to(msg, new TextDecoder().decode(dst));
    return new G2Point(p);
  }

  toBytes(): Uint8Array {
    return this.inner.compress();
  }

  isIdentity(): boolean {
    return this.inner.is_inf();
  }

  add(o: G2Point): G2Point {
    return new G2Point(this.inner.dup().add(o.inner));
  }

  sub(o: G2Point): G2Point {
    return new G2Point(this.inner.dup().add(o.inner.dup().neg()));
  }

  neg(): G2Point {
    return new G2Point(this.inner.dup().neg());
  }

  mul(s: bigint): G2Point {
    return new G2Point(this.inner.dup().mult(blstScalar(s)));
  }

  equals(o: G2Point): boolean {
    return this.inner.is_equal(o.inner);
  }
}
