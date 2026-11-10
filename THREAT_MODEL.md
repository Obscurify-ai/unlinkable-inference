# Threat model

## The claim

> The server cannot tell who sent a chat: not which account, not which
> payment, not which IP.

It does **not** claim the server cannot read a prompt. The server and the
model see the text.

## Who is who

- **Server**: honest-but-curious or malicious. Holds its whole database and
  logs, runs whatever code it likes.
- **Relay**: sees client IPs and ciphertext. Assumed not to collude with the
  server.
- **Client**: runs code the user can check (this repo; reproducible builds).

## What each party learns

| | Account | Payment | IP | Content |
|---|---|---|---|---|
| Server, at withdrawal | yes | the amount (fixed sizes) | relay's (or yours, direct) | blinded messages only |
| Server, at session use | no | no | relay's | yes |
| Relay | no | no | yes | no |

What links a session to a withdrawal would have to be in what the server sees
at both. At withdrawal it signs blinded messages; at spending it sees
unblinded messages and signatures. RFC 9474 blinding makes these independent:
no amount of computation ties one to the other. The reference server's
`/debug/db` is the server's full view; `proxy/tests/e2e.rs` asserts the two
share nothing.

## What is protected, and how

- **Account → chat**: sessions are paid with vouchers, not an account key.
  The session secret is random and used for nothing else.
- **Payment → chat**: the existing blind vouchers, plus withdrawals from an
  account into the wallet in fixed sizes.
- **IP → chat**: Oblivious HTTP through a relay.
- **Chat → chat**: one session per conversation; turns within it are linked to
  each other only.
- **Tagging a user with a unique key**: keysets are pinned; `unlinkable verify`
  compares the keys the server gives you, the keys the relay fetches and the
  published pins.
- **A website spending your wallet through the proxy**: the proxy refuses
  requests with a non-local Origin or Host and POSTs that are not JSON.

## What is not protected

- **Content**. A prompt that names you names you. A unique system prompt reused
  across sessions links them by content.
- **Collusion** between the relay and the server. Tor assumes less.
- **Timing**. A withdrawal immediately followed by a session of the same size,
  on a quiet server, is suggestive. Withdraw ahead of time; the wallet splits
  vouchers into session-sized pieces through anonymous exchanges.
- **Denominations**. Change comes back in the standard split, so its values
  say how much was left; spending those exact values later is weakly
  suggestive. `unlinkable exchange` trades them for a standard set.
- **The web app**. Its scripts come from the server. The strong claim is the
  proxy and the Android app; the web gets published script hashes.
- **Loss**. Vouchers are bearer credit. Lose the wallet file, lose them.
  `unlinkable export` makes a backup.
- **Abuse controls**. The server cannot ban a person in this mode, only refuse
  a session.

## Out of scope for v1

Free models and models that need a plan: these need a blind per-period pass,
not built yet. Sessions cover pay-as-you-go models and paid tools.
