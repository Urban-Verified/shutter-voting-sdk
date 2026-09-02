import {
  G2Point,
  buildBallot,
  initCurves,
  schnorrKeygen,
} from '../src';

beforeAll(async () => {
  await initCurves();
});

describe('high-level ballot wrapper', () => {
  it('rejects identity mpk before producing vote-revealing ciphertexts', () => {
    const { sk, vk } = schnorrKeygen();

    expect(() =>
      buildBallot({
        mpk: G2Point.identity(),
        electionId: new Uint8Array(32).fill(0xe1),
        pseudonym: new Uint8Array(32).fill(0xa1),
        sk,
        vk,
        votes: [1n],
        params: {
          numCandidates: 1,
          budget: 1,
          mode: 'exact',
          variant: 'A',
        },
        attestation: {
          electionId: new Uint8Array(32).fill(0xe1),
          pseudonym: new Uint8Array(32).fill(0xa1),
          vk: new Uint8Array(48).fill(0x33),
          weight: 1n,
          nonce: 1n,
          signature: new Uint8Array(80),
        },
      }),
    ).toThrow(/mpk is the identity/);
  });
});
