# Threat model

## The claim

> The server cannot tell which account or payment a chat came from, or which
> other chats it goes with.

It does **not** claim the server cannot read a prompt (the server and the
model see the text), and it does not hide the IP address. Anyone can hide
that with Tor or a VPN; what nobody could hide before was the account every
request had to carry.

## Who is who

- **Server**: honest-but-curious or malicious. Holds its whole database and
  logs, runs whatever code it likes. Nothing in this design depends on anyone
  else.
- **Client**: runs code the user can check (this repo; reproducible builds).
- **The user's network**: Tor or a VPN if they want their address hidden.

## What the server learns

| | Account | Payment | Address | Content |
|---|---|---|---|---|
| At withdrawal | yes | the amount (fixed sizes) | yes, unless hidden | blinded messages only |
| At session use | no | no | yes, unless hidden | yes |

What links a session to a withdrawal would have to be in what the server sees
at both. At withdrawal it signs blinded messages; at spending it sees
unblinded messages and signatures. RFC 9474 blinding makes these independent:
no amount of computation ties one to the other. The reference server's
`/debug/db` is the server's full view; `proxy/tests/e2e.rs` asserts the two
share nothing.

An address seen at both is a link. Someone who withdraws and chats from the
same home IP has hidden their account from the chat but not themselves:
use Tor or a VPN, or at least withdraw from a different network.

## What is protected, and how

- **Account → chat**: sessions are paid with vouchers, not an account key.
  The session secret is random and used for nothing else.
- **Payment → chat**: the existing blind vouchers, plus withdrawals from an
  account into the wallet in fixed sizes.
- **Chat → chat**: one session per conversation; turns within it are linked to
  each other only.
- **Plan → chat**: passes. The server sees "a Pro session", never which Pro
  account; the crowd is everyone on that plan that month.
- **Tagging a user with a unique key**: keysets are pinned; `unlinkable verify`
  compares the keys the server gives you with your pins and the published pins.
- **A website spending your wallet through the proxy**: the proxy refuses
  requests with a non-local Origin or Host and POSTs that are not JSON.

## What is not protected

- **Content**. A prompt that names you names you. A unique system prompt reused
  across sessions links them by content.
- **The address**. Hide it with Tor or a VPN.
- **Timing**. A withdrawal immediately followed by a session of the same size,
  on a quiet server, is suggestive. Withdraw ahead of time; the wallet splits
  vouchers into session-sized pieces through anonymous exchanges.
- **Denominations**. Change comes back in the standard split, so its values
  say how much was left; spending those exact values later is weakly
  suggestive. `unlinkable exchange` trades them for a standard set. Dust is
  always spent with the next session, so dust in an opening says only "this
  client had a session before".
- **Automatic top-ups**. With the account key, the proxy withdraws when the
  wallet runs low and fetches passes when they run low, in the background,
  never at the moment a session opens (unless the wallet is empty). Without
  Tor or a VPN the same address makes both, which links them.
- **The web app**. Its scripts come from the server. The strong claim is the
  proxy and the Android app; the web gets published script hashes.
- **Loss**. Vouchers are bearer credit. Lose the wallet file, lose them.
  With the account key the proxy keeps the wallet small (it tops up $1 when
  below 50¢), so a lost device costs at most about $1.50; the account balance
  is untouched. `unlinkable export` makes a backup.
- **Abuse controls**. The server cannot ban a person in this mode, only refuse
  a session.

## Passes leak the tier

A session opened with a pass shows its tier. On a plan with few users, or with
an unusual number of sessions a month, that narrows things. The allowance is
the same for everyone on a plan, and clients use a pass for every session
they open, so pass counts carry no more than "has this plan".
