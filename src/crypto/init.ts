import type { Blst } from './blst/types';
import { getBlst } from './get-blst';

let blstInstance: Blst | null = null;
let initPromise: Promise<void> | null = null;

export async function initCurves(): Promise<void> {
  if (blstInstance) return;
  if (!initPromise) {
    initPromise = (async () => {
      const blst = await getBlst();
      await new Promise<void>((resolve) => {
        if (blst.calledRun) resolve();
        else blst.onRuntimeInitialized = () => resolve();
      });
      blstInstance = blst as Blst;
    })();
    // Clear the cached promise on failure. Without this a single transient fault --
    // a fetch that lost the network, a script blocked once -- is remembered forever
    // and every later call re-throws the same error without retrying, so the only
    // recovery is a page reload. Success keeps the memo via `blstInstance` above.
    initPromise = initPromise.catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  await initPromise;
}

export function blst(): Blst {
  if (!blstInstance) {
    throw new Error(
      'BLST not initialised. Call `await initCurves()` once before using the curve layer.',
    );
  }
  return blstInstance;
}
