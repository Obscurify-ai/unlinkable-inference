# The rules

What unlinkable-inference promises, in plain words, and how each promise is
proved. The maintainer approves this file. `spec/check.py` checks every rule.

There are two kinds of proof here, and they are not equally strong:

- **Proofs about the Rust code** (P5, M7 to M11). If someone changes that
  code and breaks the rule, the proof fails.
- **Proofs about a model of the design** (ProVerif, P1 to P4; TLA+, M1 to
  M6). They show the design is right. Each step of a model names the code it
  stands for, but if the code drifts away from the model, these proofs still
  pass. The end-to-end tests, and keeping the models in step, guard that.

## Privacy

The server is the enemy here. It holds every key and every byte it was ever
sent, and can answer anything it likes.

**P1. The server cannot tell which account paid for a chat.**
Accounts put money in their wallets. Later chats happen. The server cannot
tell whose money paid for which chat. Proved for any number of pairs of
accounts at once, each withdrawing once and chatting once, and on the
condition that the money was withdrawn before the chats began (see Timing,
below).
*ProVerif, `protocol/p1_payment.pv`.*

**P2. The server cannot tell which chats go together.**
Even when it knows who paid for a first chat, it cannot tell which later
chat, paid with that chat's change, came from the same person.
*ProVerif, `protocol/p2_change.pv`, same conditions as P1.*

**P3. A pass says what an account gets, never which account.**
A session that shows a pass shows its label and month and nothing else. The
crowd it hides in is everyone given that label that month: proved for
accounts that get the same label.
*ProVerif, `protocol/p3_pass.pv`.*

**P4. Signing in gives nothing away.**
The login key the server sees never reveals the wallet's seed, how a voucher
or its change was blinded, or the secret of a session not yet opened, even
after a whole round of withdrawing, chatting and closing in front of it.
*ProVerif, `protocol/p0_seed.pv`.*

**P5. The server's storage only ever gets hashes.**
Sessions, vouchers and passes reach storage only as their SHA-256 hashes, so
a leaked database can't spend a voucher, use a pass or take over a session.
Everything the server hands storage has a type that only
`lib/src/server/stored.rs` can make, and that file either hashes what it is
given or refuses it if it holds a session secret, voucher or pass as they are
sent. Accounts are named by their API key.
*Rust's type checker; `stored.rs` is locked with these rules.*

## Money

M1 to M6 are proved by TLA+ (`ledger/Ledger.tla`), which tries every order of
every request, with retries, lost answers and two devices holding copies of
the same vouchers. It tries them on a small world: an account with 3 units
and 1 unit of promotional credit, up to 5 vouchers, 2 session secrets, 2
request digests. Mistakes in money logic almost always show up in worlds
this small, but larger ones are not checked.

**M1. No money is made or lost.** What the customer holds (account balance,
unspent vouchers, open sessions) plus what their requests cost always equals
what they put in, plus anything the server chose to write off.

**M2. The customer never pays more than their requests cost.**

**M3. A voucher is spent once, and only a voucher the server signed.**
Forging a signature is assumed impossible (RSA, RFC 9474).

**M4. An account never goes below zero.**

**M5. A lost answer never loses money.** Asking again gets the same vouchers.

**M6. Promotional credit never turns into paid money.**

M7 to M11 are proved on the Rust code itself, for every input in the range
given: M7 to M9 by trying every case in it, one by one
(`lib/examples/exhaustive_proofs.rs`); M10 and M11 by Kani, which checks all
inputs at once as a formula (`lib/src/proofs.rs`).

**M7. Any amount splits into vouchers worth exactly that amount.** Every
amount from 0 to $10,000, and every amount below a cent.

**M8. The change always fits.** The blanks a device sends when it closes a
session can hold every possible change, to the millicent: any amount up to
$1,000 for a wallet made from an account code, and for other wallets, any
amount up to a limit of their choosing, proved for limits up to $100.

**M9. Change is exactly what the session holds.** The server's change
picking, given the blanks a wallet made from an account code really sends,
finds change worth exactly the balance, never one blank twice: every balance
to the millicent up to $1,000. For blanks a client makes up, it never picks
more than asked or one blank twice: tried for every list of up to 6 blanks
against every change of up to 7 parts (270 million cases), with values from
1 to 3. Real closes send dozens of blanks; that the picking only compares
values for equality, so small values stand for all values, is an argument
from reading the code, not a machine check. (The picking only; the signing
that follows signs what was picked.)

**M10. Rounding is in the customer's favour, by less than 1/1000 of a cent.**
For every balance up to $1,099.51 (2^40 nanodollars); sessions hold far less. This is the rounding in this library and its
reference server; Obscurify's server rounds with its own code, not covered.

**M11. Withdrawals come in fixed sizes.** $1, $5, $20, $50, $100, or 1¢ to
99¢. Nothing else, for every possible amount.

## What these proofs do not cover

- **Timing.** The server sees when each account withdraws and when each
  chat opens. A chat that opens a second after the only withdrawal is linked
  to that account by the timing alone. The wallet refills ahead of time, at
  random moments, so this is rare; but by default a chat the wallet can't pay
  asks the account at once (`Policy::fund_now = false` makes it wait for a
  random refill instead). P1 and P2 assume the wallet was stocked earlier;
  `mutants.py` shows the proof fails without that.
- **The address and the words.** Hide the address with Tor or a VPN. A
  prompt that names you names you.
- **Amounts and denominations.** The privacy models give every voucher the
  same value. Change in odd values, spent later, is weakly telling
  (THREAT_MODEL.md, Denominations).
- **Several devices on one account, and recovery.** The lookups a device
  makes to rebuild a shared wallet are not modelled.
- **Obscurify's own storage and server.** M1 to M6 are proved for the
  design every storage layer must follow, not for Obscurify's Postgres code.
- **The cryptography itself.** RSA blind signatures, SHA-256, HMAC and
  Argon2 are assumed to work as published.
- **The web app's scripts**, which come from the server.

## How we know the proofs bite

`mutants.py` breaks the design and the code on purpose (no blinding, a key
handed out per account, a voucher spent twice, change minted twice, rounding
down, ...) and checks that the right proof fails each time. A break only
counts as caught when the tool ran and found it.

## Changing these rules

`APPROVED` holds the fingerprint of this file and of everything that states
or checks a rule. `check.py` fails if any of them changed since they were
approved. A change goes to the maintainer in plain words, on the Rules page
of the Obscurify admin panel; once they approve it there, a workflow records
it with `approve.py` (see `spec/README.md`). This is a tripwire, not a lock:
anyone who can push to this repo could rerun `approve.py`. What it guarantees
is that a changed rule can't pass quietly.
