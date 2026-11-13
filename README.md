# unlinkable

Use AI models without the server being able to tell which account or payment
a chat came from, or which other chats it goes with. The server still reads
the prompt, and sees your IP address unless you hide it with Tor or a VPN.
[THREAT_MODEL.md](THREAT_MODEL.md) says exactly what is and is not protected;
[SPEC.md](SPEC.md) has the wire format.

How it works, in one paragraph: your device holds a wallet of blind-signed
vouchers. Each conversation opens a session paid with a few of them and uses a
random session secret instead of an API key. When the conversation goes quiet
the session closes and the change comes back as fresh vouchers the server has
never seen. Nothing depends on a third party.

## Parts

| Crate | What | Licence |
|---|---|---|
| `core` | vouchers, blinding, wallet, sessions, key pinning | MIT or Apache-2.0 |
| `gateway` | session endpoints and voucher checks (axum) | MIT or Apache-2.0 |
| `reference-server` | gateway + in-memory storage + echo model + play money + full DB dump | MIT or Apache-2.0 |
| `proxy` | `unlinkable`: local OpenAI/Anthropic API, wallet CLI, `verify` | GPL-3.0-or-later |

## Use it with any agent

```sh
cargo install --path proxy
```

**As an MCP server** (Claude Code, Codex, anything with MCP): the agent starts
the proxy and stops it when it exits, closing its sessions. The server entry
has no tools:

```json
{"mcpServers": {"unlinkable": {"command": "unlinkable", "args": ["mcp"],
  "env": {"OBSCURIFY_API_KEY": "sk-obs1_…"}}}}
```

Claude Code then keeps talking to the server directly; only the key changes,
to a session secret from the proxy. In `.claude/settings.json`:

```json
{"apiKeyHelper": "unlinkable key",
 "env": {"ANTHROPIC_BASE_URL": "https://obscurify.ai"}}
```

One session lasts until Claude Code goes quiet for 5 minutes; the proxy tops
it up as it runs low. Codex has no key helper, so it goes through the proxy
instead, as a profile next to the normal one (`codex --profile private`):

```toml
[model_providers.obscurify-private]
name = "Obscurify (unlinkable)"
base_url = "http://127.0.0.1:8899/v1"
env_key = "OBSCURIFY_API_KEY"

[profiles.private]
model_provider = "obscurify-private"
```

**pi**: copy `integrations/pi/unlinkable.ts` to `~/.pi/agent/extensions/`. It
starts the proxy when needed and adds an `obscurify-private` provider with the
same models as your `obscurify` one; the normal provider stays.

**On its own**: `unlinkable serve` (http://127.0.0.1:8899), then use your
usual key and change only the base URL, e.g. Claude Code:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8899 ANTHROPIC_AUTH_TOKEN=sk-obs1_… \
ANTHROPIC_MODEL=deepseek/deepseek-v4.1-flash claude
```

OpenAI SDKs and curl: base URL `http://127.0.0.1:8899/v1`, your usual key.
The proxy uses that key for one thing: keeping the wallet (and this month's
passes, on a plan) topped up in the background. Chats go out with a session
secret instead and are charged exactly their tokens, down to 0.001¢.

`http://127.0.0.1:8899/_unlinkable` shows what the server received for each
request. To hide your IP address too, run the proxy behind Tor or a VPN
(`HTTPS_PROXY` / `ALL_PROXY` are honoured).

## Verify it yourself

1. Open `/_unlinkable`, or run with `--show-traffic`: requests carry a
   session secret, no cookie, no account key.
2. `unlinkable verify` compares the keys the server gives you with your pins
   and the published pins, and prints what the server received.
3. `./verify.sh` rebuilds the binaries in a pinned container and compares
   hashes with a release.
4. Run the reference stack (`compose/`), use it, then read
   `http://127.0.0.1:8250/debug/db` (everything the server has) and try to
   tie a session to the withdrawal that paid for it. `cargo test` does this
   automatically.

## Tests

`cargo test` runs the reference server and the proxy over real sockets:
withdraw, open, stream (OpenAI and Anthropic), close, change, pinning, retries
after lost answers, spent vouchers; then it reads the server's whole database
and checks nothing links.
