/**
 * Scope detection for the BLST loader.
 *
 * The regression: `get-blst` used to branch on `browser-or-node`'s `isBrowser` /
 * `isNode` and `throw` at *module scope* when neither matched. A Web Worker matches
 * neither — it has no `window`, so `isBrowser` is false, and no `process`, so
 * `isNode` is false — so any app that ran verification off the main thread died on
 * import with "Uncaught Error: platform not supported." before its own code ran.
 * The sx-monorepo verify-tally button did exactly that.
 *
 * Two properties are pinned here:
 *   1. Importing the module never throws, whatever the scope. An import-time throw
 *      is unrecoverable and points at this file instead of the caller.
 *   2. A worker scope resolves through `importScripts`, not through the DOM branch
 *      (`document.createElement`, which a worker does not have).
 */

describe('getBlst scope detection', () => {
  const saved = {
    self: (globalThis as any).self,
    WorkerGlobalScope: (globalThis as any).WorkerGlobalScope,
    document: (globalThis as any).document,
    fetch: (globalThis as any).fetch
  };

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete (globalThis as any)[k];
      else (globalThis as any)[k] = v;
    }
    jest.resetModules();
  });

  it('imports without throwing in a worker-like scope', async () => {
    class WorkerGlobalScope {}
    const scope: any = new WorkerGlobalScope();
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = scope;
    delete (globalThis as any).document;

    await expect(import('../src/crypto/get-blst')).resolves.toBeDefined();
  });

  it('loads via importScripts in a classic worker, never via the DOM', async () => {
    class WorkerGlobalScope {}
    const scope: any = new WorkerGlobalScope();
    scope.location = { origin: 'https://example.test' };
    scope.importScripts = jest.fn(() => {
      // What the real glue does: extend the pre-seeded module object. `G2` is its
      // last assignment, so it doubles as the "script ran to completion" marker.
      scope.blst.G2 = () => 'g2';
    });
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = scope;
    delete (globalThis as any).document;

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    const blst = await getBlst();
    expect(scope.importScripts).toHaveBeenCalledWith('/blst.js');
    expect(typeof blst.G2).toBe('function');
  });

  // The glue resolves blst.wasm against `self.location.href`, which inside a
  // bundled worker is the worker chunk's URL -- so without `locateFile` it fetches
  // /assets/blst.wasm and 404s. This applies to BOTH worker flavours, not just the
  // module one.
  it('points locateFile at the site root, not at the worker chunk', async () => {
    class WorkerGlobalScope {}
    const scope: any = new WorkerGlobalScope();
    scope.location = { origin: 'https://example.test' };
    scope.importScripts = jest.fn(() => {
      scope.blst.G2 = () => 'g2';
    });
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = scope;
    delete (globalThis as any).document;

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    const blst = await getBlst();
    expect(blst.locateFile('blst.wasm')).toBe('https://example.test/blst.wasm');
  });

  it('stubs importScripts for the glue in a module worker, then removes it', async () => {
    class WorkerGlobalScope {}
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = globalThis;
    (globalThis as any).location = { origin: 'https://example.test' };
    Object.setPrototypeOf(globalThis, WorkerGlobalScope.prototype);
    delete (globalThis as any).document;
    delete (globalThis as any).importScripts;

    // Emscripten decides its environment with `typeof importScripts == 'function'`
    // and never calls it. Without the stub it concludes SHELL, skips the worker
    // branch and never installs a wasm reader -- failing far from the cause.
    (globalThis as any).fetch = jest.fn(async () => ({
      ok: true,
      text: async () =>
        'globalThis.blst.sawWorkerEnv = (typeof importScripts == "function");' +
        'globalThis.blst.G2 = function () { return "g2"; };'
    }));

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    const blst = await getBlst();
    expect(blst.sawWorkerEnv).toBe(true);
    expect(typeof blst.G2).toBe('function');
    // Removed again, or the classic branch would take it on a later call.
    expect('importScripts' in (globalThis as any)).toBe(false);

    Object.setPrototypeOf(globalThis, Object.prototype);
    delete (globalThis as any).location;
  });

  // The live failure on Chrome: a module worker *has* `importScripts` on its global
  // and throws "Module scripts don't support importScripts()." when it is called.
  // Presence is therefore true in exactly the scope where it cannot be used, so the
  // loader must call it and fall back on throw rather than feature-detect.
  it('falls back to eval when importScripts exists but throws', async () => {
    class WorkerGlobalScope {}
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = globalThis;
    (globalThis as any).location = { origin: 'https://example.test' };
    Object.setPrototypeOf(globalThis, WorkerGlobalScope.prototype);
    delete (globalThis as any).document;

    const importScripts = jest.fn(() => {
      throw new TypeError(
        "Failed to execute 'importScripts' on 'WorkerGlobalScope': Module scripts don't support importScripts()."
      );
    });
    (globalThis as any).importScripts = importScripts;
    (globalThis as any).fetch = jest.fn(async () => ({
      ok: true,
      text: async () => 'globalThis.blst.G2 = function () { return "g2"; };'
    }));

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    const blst = await getBlst();
    expect(importScripts).toHaveBeenCalledWith('/blst.js');
    expect((globalThis as any).fetch).toHaveBeenCalledWith('/blst.js');
    expect(typeof blst.G2).toBe('function');
    // Left in place: the engine owns it, the loader only borrowed a call.
    expect((globalThis as any).importScripts).toBe(importScripts);

    Object.setPrototypeOf(globalThis, Object.prototype);
    delete (globalThis as any).importScripts;
    delete (globalThis as any).location;
  });

  it('surfaces a fetch failure by status once importScripts is unusable', async () => {
    class WorkerGlobalScope {}
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = globalThis;
    (globalThis as any).location = { origin: 'https://example.test' };
    Object.setPrototypeOf(globalThis, WorkerGlobalScope.prototype);
    delete (globalThis as any).document;
    (globalThis as any).importScripts = () => {
      throw new TypeError("Module scripts don't support importScripts().");
    };
    (globalThis as any).fetch = jest.fn(async () => ({
      ok: false,
      status: 404,
      statusText: 'Not Found'
    }));

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    await expect(getBlst()).rejects.toThrow(/Failed to load BLST: 404/);

    Object.setPrototypeOf(globalThis, Object.prototype);
    delete (globalThis as any).importScripts;
    delete (globalThis as any).location;
  });

  it('rejects when the glue does not evaluate to completion', async () => {
    class WorkerGlobalScope {}
    const scope: any = new WorkerGlobalScope();
    scope.location = { origin: 'https://example.test' };
    // Seeds the module object but never assigns G2 -- presence of `blst` alone
    // must not be read as success, since the loader seeds it itself.
    scope.importScripts = jest.fn(() => {});
    (globalThis as any).WorkerGlobalScope = WorkerGlobalScope;
    (globalThis as any).self = scope;
    delete (globalThis as any).document;

    jest.resetModules();
    const { getBlst } = await import('../src/crypto/get-blst');
    await expect(getBlst()).rejects.toThrow(/failed to initialize/i);
  });

  it('rejects rather than throws when no scope matches', async () => {
    delete (globalThis as any).WorkerGlobalScope;
    delete (globalThis as any).document;
    jest.resetModules();
    jest.doMock('browser-or-node', () => ({ isBrowser: false, isNode: false }));
    const { getBlst } = await import('../src/crypto/get-blst');
    // A rejected promise, not a synchronous throw: the caller gets to handle it.
    await expect(getBlst()).rejects.toThrow(/platform not supported/);
    jest.dontMock('browser-or-node');
  });
});
