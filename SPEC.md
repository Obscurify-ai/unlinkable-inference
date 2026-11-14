# Unlinkable sessions: wire format

Version 1. All JSON. Binary values are base64url without padding. Amounts are
integer cents unless named `_usd`, which are exact decimal strings.

## Parties

- **Client**: holds the wallet. The proxy (`unlinkable`), and later the
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
obscurify.ai live in `core/keys/obscurify.ai.pins`.

## Endpoints

None of them reads a cookie or stores an IP. Errors are
`{"error": {"message", "type", "spent"?}}`.

| Request | Auth | Body | Answer |
|---|---|---|---|
| `POST /u/sessions` | none | `{"vouchers": [codes], "secret_hash"}` | session status |
| `GET /u/sessions/current` | session | | session status |
| `POST /u/sessions/topup` | session | `{"vouchers": [codes]}` | session status |
| `POST /u/sessions/close` | session | `{"blanks": [blanks]}` | change |
| `POST /u/exchange` | none | `{"vouchers": [codes], "blanks": [blanks]}` | change |
| `POST /u/withdraw` | account API key | `{"amount_cents", "blanks": [blanks]}` | change |
| `GET /u/passes` | account API key | | `{"tier", "period", "remaining"}` |
| `POST /u/passes` | account API key | `{"tier", "period", "blinded": [b64]}` | `{"tier", "period", "blind_signatures", "remaining"}` |

- **Session status**: `{"balance_usd", "family", "idle_timeout_seconds", "closed", "tier"?}`.
- **Change**: `{"change_cents", "family", "signed": [{"index", "blind_signature"}]}`;
  `index` points into the request's `blanks`.
- **Session auth**: `Authorization: Bearer sk-unl1_<32 random bytes>`. The
  client picks the secret and sends only `secret_hash` = SHA-256(secret), hex,
  when opening. The same secret is the API key for model and tool requests.

Rules:

- **Open** needs at least the server's minimum (10¢ by default) and spends
  every voucher or none. Vouchers must share a family and not
  repeat; up to 64. If any were spent before: 409 with `spent` = their indexes,
  and nothing is spent. A repeat open with the same `secret_hash` (the same
  vouchers, all spent by the first) returns the existing session and spends
  nothing; with any voucher not yet spent it is someone else's secret: 409
  `secret_taken`, nothing spent, pick another. With `"pass"`, the session gets the
  pass's tier (its plan's models); a pass opens one session (409
  `pass_spent` after that) and only in its own month.
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
  or $100 from the account's withdrawable balance (credit that was never paid
  for stays in the account). A repeat with the same blanks gets the same answer.
- Sessions refuse model requests after `idle_timeout_seconds` without one but
  can always be closed for change: an open session's balance is never taken.

## Passes

A pass proves "this session's holder has plan X this month" without saying
which account. It is a partially blind RSA signature
(draft-irtf-cfrg-partially-blind-rsa, SHA-384, PSS, deterministic) under the
keyset's `pass_key`, with public metadata `unlinkable-pass:v1:<tier>:<YYYY-MM>`;
the client blinds against the key derived for that metadata. Tiers:
`pay_as_you_go`, `casual`, `pro`. Text form:
`obp1.<tier>.<YYYY-MM>.<message>.<signature>`, message 32 random bytes; spent
as SHA-256(message).

An account asks with its API key for passes at its own tier, for the current
month, up to a monthly allowance set by the server. The server learns how many
passes an account took, never which sessions used them. A repeat request with
the same blinded messages gets the same answer.

## Abuse limits

Servers should rate-limit `/u/*` per client address (Obscurify: in memory,
per hour) and may set a higher session minimum. Neither involves storing the
address.
