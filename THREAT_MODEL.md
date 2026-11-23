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
| At withdrawal | yes | the amount (fixed sizes, or the last of a balance under $1) | yes, unless hidden | blinded messages only |
| At session use | no | no | yes, unless hidden | yes |

What links a session to a withdrawal would have to be in what the server sees
at both. At withdrawal it signs blinded messages; at spending it sees
unblinded messages and signatures. RFC 9474 blinding makes these independent:
no amount of computation ties one to the other. The reference server's
`/debug/db` is the server's full view; `cli/tests/e2e.rs` asserts the two
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
- **What an account is given → chat**: passes. Where the server gives some
  accounts more than others (certain models, an allowance), a session proves
  it with a pass. The server sees "a session that holds label X", never which
  account; the crowd is everyone given that label that month. A session that
  needs no pass shows none, so it hides among all sessions.
- **Tagging a user with a unique key**: keysets are pinned; `unlinkable-inference verify`
  compares the keys the server gives you with your pins and the published pins.
- **A website spending your wallet through the proxy**: the proxy refuses
  requests with a non-local Origin or Host and POSTs that are not JSON.

## What is not protected

- **Content**. A prompt that names you names you. A unique system prompt reused
  across sessions links them by content.
- **The address**. Hide it with Tor or a VPN.
- **Timing**. Whatever the amounts, a withdrawal followed a second later by a session opening
  or topping up points at the account, on a quiet server most of all. Clients keep the wallet
  stocked ahead of time (at least $2, $5 at a time) and ask the account at moments of its own
  (the app starting, a sign-in, a payment) and at random times 5 to 30 minutes apart, so most
  conversations never need it. When one does (the wallet is empty, or short of a pass), the
  account is asked at once by default, so nobody is kept waiting: those two requests are then
  seconds apart. `Policy::fund_now = false` (the proxy's `Settings::fund_now`) makes the
  conversation wait instead, until a random while after a contact 30 s to 5 min away.
  Under $1 the account's balance moves in fixed sizes (50¢, 20¢, 10¢, 5¢, 2¢, 1¢).
  An app's own signed-in requests when it opens (balance, plan) are as telling as a withdrawal
  for a chat started a few seconds later. Sessions opened with a pass and no money have no
  amount to compare.
- **Denominations**. Change comes back in the standard split, so its values
  say how much was left; spending those exact values later is weakly
  suggestive. `unlinkable-inference exchange` trades them for a standard set. Dust is
  always spent with the next session, so dust in an opening says only "this
  client had a session before".
- **Automatic top-ups**. With the account key, the proxy and apps keep the wallet and passes
  stocked in the background (at least $2, $5 at a time), at the moments described under Timing.
  A pass the wallet lacks for a label the account gets waits the same way; a label the account
  wasn't offered at the last contact is refused at once (a plan bought in the app is a moment of
  its own: the app says so and the account is asked then). Without Tor or a VPN the same address
  makes both the account's requests and the sessions', which links them whatever the timing.
- **The web app**. Its scripts come from the server. The strong claim is the
  proxy and the Android app; the web gets published script hashes.
- **One wallet per account**. Devices signed in with the same code share the wallet: a device
  running low looks up the account's own withdrawals (already tied to the account) and the
  anonymous lists of unclaimed sessions and spent vouchers, the same lookups as a restore. The
  server learns nothing new: a session in use is never listed, so no device touches another's,
  and which device spends a voucher is not visible.
- **Loss**. Vouchers are bearer credit. A wallet seeded from the account
  number loses nothing: every voucher, pass and session secret is derived from
  the number, and the next sign-in rebuilds the wallet and closes stranded
  sessions for their change. A wallet without the number (vouchers bought or
  imported) is lost with its file; `unlinkable-inference export` makes a backup.
  Either way the wallet stays small (it tops up $5 when below $2) and the
  account balance is untouched.
- **Abuse controls**. The server cannot ban a person in this mode, only refuse
  a session.

## Passes show their label

A session that presents a pass shows the label, and so belongs to the group of
accounts given that label this month. A label few accounts get, or an unusual
mix of labels in one session, narrows things. What limits it:

- A session presents a pass only when the server asks for that label, so a
  conversation that needs none looks like everyone else's.
- The allowance of a label is the same for every account that gets it, so
  pass counts carry no more than "gets this label".
- Servers should keep labels few and broad, and tie them to what a request
  needs (this model group), not to who the account is (this plan).

The proxy's helper session (`unlinkable-inference key`, for agents that talk
to the server directly) is the exception: nothing sees the server ask, so it
presents one pass of each label the account gets when it opens.
