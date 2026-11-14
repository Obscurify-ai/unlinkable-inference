// @obscurify/unlinkable: unlinkable sessions in a web page.
//
// The page's chat requests go out with a session secret paid from a wallet of
// blind vouchers, and with no cookie, so the server cannot tell which account
// a conversation belongs to, or which conversations go together. Everything
// comes from the account number, so when the browser forgets (Tor Browser
// closing), the next sign-in brings the wallet back. Nothing is lost.
//
//   import * as unlinkable from '@obscurify/unlinkable';
//   const { loginKey, seed } = await unlinkable.keys(number); // send loginKey to sign in
//   const u = await unlinkable.connect({ seed, apiKey });
//   const res = await u.fetch('/v1/chat/completions', { method: 'POST', body }, { chat: conversationId });
import init, { accountKeys, newAccountNumber, Manager } from './unlinkable_wasm.js';

let loaded;

/** Load the WebAssembly module (once). Pass `wasmUrl` if it is not next to this file. */
export function load(wasmUrl) {
    loaded ||= init(wasmUrl ? { module_or_path: wasmUrl } : undefined);
    return loaded;
}

/** `{ loginKey, seed }` for a 16-digit account number. Send `loginKey` to sign in
 *  instead of the number; keep `seed` (hex) for `connect`. Slow on purpose (~1 s). */
export async function keys(number) {
    await load();
    const k = accountKeys(number);
    return { loginKey: k.login_key, seed: k.seed };
}

/** A new random account number, made here: the server never learns it. */
export async function newNumber() {
    await load();
    return newAccountNumber();
}

/**
 * Start private sessions. Closes sessions left from last time, brings back
 * whatever a lost browser left behind, tops the wallet up, and from then on
 * closes quiet conversations' sessions and tops up every `tickMs`.
 *
 *   seed         hex, from keys()
 *   apiKey       the account's API key (or an async function for it), used only
 *                to top the wallet up; without it the wallet spends what it holds
 *   server       the API's origin (default: this page's)
 *   storage      where the wallet is kept (default localStorage), under `name`
 *   replyHeader  a response header naming a reply the server holds for later
 */
export async function connect({ seed, apiKey, server = location.origin, storage = localStorage, name = 'unlinkable', replyHeader, tickMs = 30000 }) {
    await load();
    const key = typeof apiKey === 'function' ? await apiKey() : apiKey;
    const m = await Manager.connect(server, seed, storage.getItem(name), key ?? null);
    const save = () => {
        const s = m.state();
        if (s) storage.setItem(name, s);
    };
    const run = async (p) => {
        try { return await p; } finally { save(); }
    };
    await run(m.start());
    const timer = setInterval(() => run(m.tick()).catch(() => {}), tickMs);

    return {
        /** fetch() for conversation `chat` (or held reply `reply`), with its
         *  session secret and no cookie. Tops the session up when it runs out. */
        async fetch(url, init = {}, { chat = 'default', reply } = {}) {
            const held = reply ? await m.reply(reply) : null;
            let secret = held || (await run(m.session(chat)));
            for (let attempt = 0; ; attempt++) {
                const headers = new Headers(init.headers || {});
                headers.set('Authorization', 'Bearer ' + secret);
                const res = await fetch(url, { ...init, headers, credentials: 'omit' });
                if (attempt < 4 && !held && res.status === 402) {
                    await run(m.ranOut(secret, attempt)).catch(() => {});
                    continue;
                }
                if (attempt < 4 && !held && res.status === 401) {
                    await m.expired(secret);
                    secret = await run(m.session(chat));
                    continue;
                }
                const id = replyHeader && res.headers.get(replyHeader);
                if (id) await run(m.noteReply(id, secret));
                return res;
            }
        },
        /** `{ paid_cents, passes }`, or null while busy. */
        summary: () => m.summary(),
        stop: () => clearInterval(timer),
    };
}

/** Signing out: drop the saved wallet (it comes back from the number). */
export function forget({ storage = localStorage, name = 'unlinkable' } = {}) {
    storage.removeItem(name);
}
