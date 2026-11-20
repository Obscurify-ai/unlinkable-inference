# Unlinkable inference: wire format

Version 1. All JSON. Binary values are base64url without padding. Amounts are
integer cents unless named `_usd`, which are exact decimal strings.

## Parties

- **Client**: holds the wallet. The proxy (`unlinkable-inference`), and later the
  Android and web apps.
- **Server**: runs the gateway. Sees each request's content and the address it
  came from. Hiding that address is up to the client's network (Tor, a VPN);
  the protocol does not depend on any third party.

## Vouchers

RFC 9474 blind RSA, `RSABSSA-SHA384-PSS-Deterministic`, 2048-bit keys. One key
per value and per family:

- values: 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000,
  50000, 100000, 200000, 500000 cents;
- families: `paid` (bought with money) and `promo` (promotional credit). A
  session is funded by one family and its change comes back in that family.

A voucher is `obv1.<cents>.<key_id>.<message>.<signature>`: `message` is 32
random bytes chosen by the client, `key_id` is the first 8 bytes (16 hex
characters) of SHA-256 of the key's DER SubjectPublicKeyInfo. The server
records a spent voucher as SHA-256(message), hex, and nothing else.

**Dust** vouchers carry values below a cent, in millicents (1/1000 of a
cent): 1, 2, 5, 10, 20, 50, 100, 200, 500, one key each per family, listed in
`dust_paid` / `dust_promo`. Text form `obd1.<millicents>.<key_id>.<message>.<signature>`.
All amounts on the server are kept in millicents.

A **blank** is a message the client blinded against one key:
`{"denomination_cents", "key_id", "blinded_message", "dust"?}` (value in
millicents when `dust` is true). The server returns a
blind signature; the client unblinds it into a voucher the server has never
seen.

## Keyset and pinning

`GET /u/keys`:

```json
{"scheme": "RSABSSA-SHA384-PSS-Deterministic",
 "paid":  [{"denomination_cents": 1, "key_id": "…", "public_key_der": "…"}, …],
 "promo": […],
 "dust_paid": [same, values in millicents], "dust_promo": […],
 "pass_key": {"key_id": "…", "public_key_der": "…"}}
```

Its **fingerprint** is `ks1-` + the first 32 hex characters of SHA-256 of the
JSON serialisation with both key lists sorted by value, fields in the order
above. Clients accept a keyset only if its fingerprint is pinned (built into
the release, given with `--pin`, or pinned on first use for servers with no
built-in pins) and every `key_id` matches its key. Published pins for
obscurify.ai live in `lib/keys/obscurify.ai.pins`.

## Endpoints

None of them reads a cookie or stores an IP. Errors are
`{"error": {"message", "type", "spent"?, "available_cents"?}}`.

| Request | Auth | Body | Answer |
|---|---|---|---|
| `POST /u/sessions` | none | `{"vouchers": [codes], "secret_hash"}` | session status |
| `GET /u/sessions/current` | session | | session status |
| `POST /u/sessions/topup` | session | `{"vouchers": [codes]}` | session status |
| `POST /u/sessions/pass` | session | `{"pass": code}` | session status |
| `POST /u/sessions/close` | session | `{"blanks": [blanks]}` | change |
| `POST /u/exchange` | none | `{"vouchers": [codes], "blanks": [blanks]}` | change |
| `POST /u/withdraw` | account API key | `{"amount_cents", "blanks": [blanks]}` | change |
| `GET /u/passes` | account API key | | `{"period", "labels": [{"label", "remaining"}]}` |
| `POST /u/passes` | account API key | `{"label", "period", "blinded": [b64]}` | `{"label", "period", "blind_signatures", "remaining"}` |

- **Session status**: `{"balance_usd", "family", "idle_timeout_seconds", "closed", "labels"?, "repeat"?}`.
- **Change**: `{"change_cents", "family", "signed": [{"index", "blind_signature"}]}`;
  `index` points into the request's `blanks`.
- **Session auth**: `Authorization: Bearer sk-unl1_<32 random bytes>`. The
  client picks the secret and sends only `secret_hash` = SHA-256(secret), hex,
  when opening. The same secret is the API key for model and tool requests.

Rules:

- **Open** needs at least the server's minimum (10¢ by default) and spends
  every voucher or none. Vouchers must share a family and not
  repeat; up to 64. If any were spent before: 409 with `spent` = their indexes,
  and nothing is spent. A repeat open with the same `secret_hash` and exactly the
  vouchers that opened it returns the existing session with `"repeat": true` and
  spends nothing; with any other vouchers it is someone else's secret: 409
  `secret_taken`, nothing spent, pick another. Devices sharing an account's wallet
  derive the same secrets and hold copies of the same vouchers, so a client that
  gets `repeat` on a first try (not a retry after a lost response) treats it as
  another device's session: those vouchers are spent, pick another secret. With `"pass"`, that pass
  is presented as the session opens (see Passes).
- **Close** rounds the balance **up** to the next millicent (a session never
  costs more than its tokens) and signs the standard split (largest first,
  1-2-5 steps) of it: whole cents from the normal blanks, the rest from dust
  blanks. So the client sends blanks able to hold any amount up to the
  balance plus one cent (per power of ten one 5, two 2s and one 1) and dust
  blanks for any amount under a cent (500, 200, 200, 100, 50, 20, 20, 10, 5,
  2, 2, 1). Change: `{"change_cents", "dust_millicents", …}`. A repeat close with the same blanks gets the
  same answer; a different one gets 410.
- **Exchange** and **withdraw** sign every blank (dust or not); the blanks must
  add up to exactly the vouchers' total, or the amount, in millicents. Withdrawals are $1, $5, $20, $50
  or $100, or any amount under $1 (the last of a balance), from the account's balance. One the
  account can't cover is 402 with `available_cents`, what it can; clients take that when it is
  at least a session's minimum, and leave less in the account. A repeat with the same blanks
  gets the same answer.
- Sessions refuse model requests after `idle_timeout_seconds` without one but
  can always be closed for change: an open session's balance is never taken.

## One wallet per account

A seeded wallet is a function of the account's seed and the server's records, so every device
signed in with the account's code spends one wallet. A device whose wallet runs low first
rebuilds it (`GET /u/issued` with the account key, `GET /u/sessions/unclaimed`, `GET /u/spent`):
that finds what the other devices withdrew, and the change of sessions they closed, before it
takes more from the account. `GET /u/sessions/unclaimed` lists a session only once it is closed
or unused for 15 minutes (`UNCLAIMED_AFTER_SECS`), so a device never closes a session another
device is using. A voucher two devices hold is spent by whichever uses it first; the other gets
409 `spent` (or `repeat`) and drops it.

Clients open a conversation's session with the server's minimum (10¢) and top it up as it is
used, so a small balance spreads over many open conversations; seeded withdrawals arrive in 10¢
pieces for that. A device whose own quiet sessions hold the last of the money closes them for
their change when nothing else can fund the conversation in use. After the account's code
changes, a device that knew the old code or number keeps that seed and rebuilds with it too, so
money withdrawn or left in sessions before the change is still found.

## Passes

A pass proves "this session's holder was given X this month" without saying
which account. X is a **label**: 1 to 32 of `a-z`, `0-9`, `_`, `-`, chosen by
the server for whatever it gives some accounts and not others (a group of
models, an allowance). The protocol and this library give labels no meaning:
which accounts get which labels, and what a label is good for, is the
server's business.

A pass is a partially blind RSA signature (draft-irtf-cfrg-partially-blind-rsa,
SHA-384, PSS, deterministic) under the keyset's `pass_key`, with public
metadata `unlinkable-inference-pass:v1:<label>:<YYYY-MM>`; the client blinds
against the key derived for that metadata. Text form:
`obp1.<label>.<YYYY-MM>.<message>.<signature>`, message 32 random bytes; spent
as SHA-256(message).

**Getting them.** `GET /u/passes` (account API key) lists the labels the
account can get this month and how many of each are left. `POST /u/passes`
asks for some with one label; the server signs them if the account gets that
label (403 otherwise, 429 `pass_limit` past the month's allowance). It learns
how many passes of each label an account took, never which sessions used
them. A repeat request with the same blinded messages gets the same answer.
Clients keep a small stock of each label and refill it in the background, so
the moment an account asks says nothing about any one conversation.

**Using them.** A session opens with no pass. When a request needs one the
session has not presented, the server refuses it with **403**, the response
header `X-Pass-Required: <label>`, and
`{"error": {"type": "pass_required", "pass": "<label>", "message"}}`. The
client presents one with that label (`POST /u/sessions/pass`, the session's
secret) and sends the request again. With none to present it sends the request
once more as it was (a server may then serve it another way, at another price),
and shows the error if that is refused too.
A server may ask again later (a label that stands for an allowance that runs
out) or for another label; clients stop after a few rounds. A client never
presents a pass it was not asked for, so a session shows only what its
requests needed. A pass works once and only in its own month: presented again
by the same session (a retry) nothing changes; by another, 409 `pass_spent`,
and the client drops it and presents the next (devices sharing a wallet hold
copies of the same passes).

**0.1 clients** called the label `tier`: they send `{"tier", …}` to
`POST /u/passes` and read `tier` in the answer, in `GET /u/passes`
(`{"tier", "period", "remaining"}`) and in the session status, and present
their pass in `POST /u/sessions`. The server module still accepts and answers
in those words when asked that way, and a server's backend may name one label
in `GET /u/passes` for them; their records in `GET /u/issued` keep the kind
`passes` (0.2 clients' are `pass`, which 0.1 clients skip).

## Abuse limits

Servers should rate-limit `/u/*` per client address (Obscurify: in memory,
per hour) and may set a higher session minimum. Neither involves storing the
address.
