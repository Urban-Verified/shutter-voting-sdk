import { isNode } from "browser-or-node";

declare global {
    interface Window {
        blst: any;
    }
}

/**
 * Where the browser and worker builds fetch the Emscripten glue from.
 *
 * `blst.js` is a classic script that assigns a global `blst`; it is not an ES
 * module and cannot be `import()`ed. Every branch below is a different way of
 * getting a classic script evaluated in a global scope.
 */
const BLST_URL = '/blst.js';

/** A window with a DOM — the only scope that can append a <script> tag. */
const hasDocument = typeof document !== 'undefined' && !!document?.head;

/**
 * A Web Worker of either flavour.
 *
 * Checked via `self` rather than `window`, which is the whole point: a worker has
 * no `window`, so `browser-or-node`'s `isBrowser` is false there, and its `isNode`
 * is false too. This module used to `throw` in that gap at *module scope*, so any
 * app that ran verification off the main thread died on import with
 * "platform not supported." before a single line of its own code ran.
 */
const isWorker =
    typeof self !== 'undefined' &&
    typeof (globalThis as any).WorkerGlobalScope !== 'undefined' &&
    self instanceof (globalThis as any).WorkerGlobalScope;

async function loadInDocument(): Promise<any> {
    if (!window.blst) {
        const script = document.createElement('script');
        script.src = BLST_URL;

        await new Promise((resolve, reject) => {
            script.onload = resolve;
            script.onerror = () => reject(new Error("Failed to load BLST"));
            document.head.appendChild(script);
        });

        if (!window.blst) {
            throw new Error("BLST failed to initialize after loading");
        }
    }
    return window.blst;
}

/**
 * Point the glue at the site root for its `.wasm`.
 *
 * Emscripten resolves `blst.wasm` against `self.location.href`, which inside a
 * bundled worker is the worker chunk's URL — so it would fetch something like
 * `/assets/blst.wasm` or `/src/helpers/blst.wasm` and 404. The `<script>` path does
 * not have this problem because `document.currentScript.src` really is `/blst.js`.
 *
 * Seeding the module object works because the glue opens with
 * `var blst = typeof blst != 'undefined' ? blst : {}` — the documented pre-run hook.
 */
function seedModule(scope: any): void {
    const existing = scope.blst && typeof scope.blst === 'object' ? scope.blst : {};
    if (!existing.locateFile) {
        existing.locateFile = (path: string) =>
            new URL(path, scope.location.origin).href;
    }
    scope.blst = existing;
}

/** Set once BLST is initialised, so a second call does not re-evaluate the glue. */
let workerBlst: any = null;

async function loadInWorker(): Promise<any> {
    if (workerBlst) return workerBlst;
    const scope = self as any;
    seedModule(scope);

    // `importScripts` is NOT a usable feature test. Chrome defines it on a *module*
    // worker's global and then throws
    //   "Module scripts don't support importScripts()."
    // when it is called, so `typeof scope.importScripts === 'function'` is true in
    // exactly the scope where it cannot be used. The only reliable check is to call
    // it and see. A throw here costs nothing: it fails before fetching anything, and
    // a genuine failure (404, syntax error) falls through to the fetch path, which
    // reports the cause properly instead of swallowing it.
    let loaded = false;
    if (typeof scope.importScripts === 'function') {
        try {
            scope.importScripts(BLST_URL);
            loaded = true;
        } catch {
            loaded = false;
        }
    }

    if (!loaded) {
        // Module worker: no usable `importScripts`, and `import()` cannot load a
        // classic script. Indirect eval is what is left, and it is also the most
        // faithful option - it runs in global scope in sloppy mode, exactly as a
        // <script> tag would, whereas wrapping the glue in a Blob module would
        // impose strict mode on code never written for it. Needs
        // `script-src 'unsafe-eval'`.
        const res = await fetch(BLST_URL);
        if (!res.ok) {
            throw new Error(`Failed to load BLST: ${res.status} ${res.statusText}`);
        }
        const source = await res.text();

        // The glue picks its environment with `typeof importScripts == 'function'`
        // and never calls it. Where the engine exposes it (Chrome) that test already
        // passes; where it does not, the glue would conclude ENVIRONMENT_IS_SHELL,
        // skip the web/worker branch and never install a wasm reader - failing far
        // from the cause. Stub it only in that case, and remove it afterwards.
        const stubbed = typeof scope.importScripts !== 'function';
        if (stubbed) {
            scope.importScripts = () => {
                throw new Error('importScripts is not available in a module worker');
            };
        }
        try {
            (0, eval)(source);
        } finally {
            if (stubbed) delete scope.importScripts;
        }
    }

    // Not `if (!scope.blst)`: `seedModule` already made that truthy, so presence
    // proves nothing here. `G2` is assigned on the last line of the glue, so its
    // absence means the script did not evaluate to completion.
    if (typeof scope.blst?.G2 !== 'function') {
        throw new Error("BLST failed to initialize after loading");
    }
    workerBlst = scope.blst;
    return workerBlst;
}

/**
 * Resolve the BLST module for the current scope.
 *
 * Deliberately a function that *rejects* on an unsupported platform rather than a
 * module that throws while being imported. An import-time throw is unrecoverable
 * and unattributable: it takes down the importing module before any caller exists
 * to catch it, and the stack points at this file rather than at whatever asked for
 * a signature.
 */
export const getBlst: () => Promise<any> = () => {
    if (isWorker) return loadInWorker();
    if (hasDocument) return loadInDocument();
    if (isNode) return import('./blst/blst').then(module => module.default);
    return Promise.reject(
        new Error(
            "platform not supported: no document, worker scope, or Node runtime detected."
        )
    );
};
