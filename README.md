# unlinkable

Use AI models without the server being able to tell who sent each chat: not
which account, not which payment, not which IP. The server still reads the
prompt; see [THREAT_MODEL.md](THREAT_MODEL.md) for exactly what is and is not
protected, and [SPEC.md](SPEC.md) for the wire format.

How it works, in one paragraph: your device holds a wallet of blind-signed
vouchers. Each conversation opens a session paid with a few of them, uses a
random session secret instead of an API key, and sends every request through a
relay sealed with Oblivious HTTP. When the conversation goes quiet the session
closes and the change comes back as fresh vouchers the server has never seen.

## Parts

| Crate | What | Licence |
|---|---|---|
| `core` | vouchers, blinding, wallet, sessions, OHTTP client, key pinning | MIT or Apache-2.0 |
| `gateway` | session endpoints, voucher checks, OHTTP gateway (axum) | MIT or Apache-2.0 |
| `relay` | a minimal streaming OHTTP relay | MIT or Apache-2.0 |
| `reference-server` | gateway + in-memory storage + echo model + play money + full DB dump | MIT or Apache-2.0 |
| `proxy` | `unlinkable`: local OpenAI/Anthropic API, wallet CLI, `verify` | GPL-3.0-or-later |

## Use it with any agent

```sh
cargo install --path proxy
export UNLINKABLE_RELAY=https://<relay>/obscurify   # without it the server sees your IP
unlinkable withdraw 5 --api-key sk-obs1_…           # do this ahead of time
unlinkable serve                                     # http://127.0.0.1:8899
```

Claude Code:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8899 ANTHROPIC_AUTH_TOKEN=anything \
ANTHROPIC_MODEL=deepseek/deepseek-v4.1-flash claude
```

OpenAI SDKs and curl: base URL `http://127.0.0.1:8899/v1`, any API key. The
key you give the proxy never leaves your machine; it only names a session
(`--per key`), or is ignored in favour of one session per conversation
(`--per conversation`, the default).

`http://127.0.0.1:8899/_unlinkable` shows what left your device for each
request: who saw your IP, what they could read, and what the server read.

## Verify it yourself

1. Open `/_unlinkable`, or run with `--show-traffic`: requests go to the
   relay, carry a session secret, no cookie, no account key.
2. `unlinkable verify` compares the keys the server gives you with the keys the
   relay fetches and the published pins, and prints what each party received.
3. `./verify.sh` rebuilds the binaries in a pinned container and compares
   hashes with a release.
4. Run the reference stack (`compose/`), use it, then read
   `http://127.0.0.1:8250/debug/db` (everything the server has) and try to
   tie a session to the withdrawal that paid for it. `cargo test` does this
   automatically.

## Tests

`cargo test` runs the reference server, a real relay and the proxy over real
sockets: withdraw, open, stream (OpenAI and Anthropic), close, change, pinning,
retries after lost answers, spent vouchers, direct mode; then it reads the
server's whole database and checks nothing links.
