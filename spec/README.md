# Proofs

`RULES.md` says what this library promises, in plain words. Everything else
here proves it.

| Rules | Tool | Files | What it checks |
|---|---|---|---|
| P1 to P4 | [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) | `protocol/` | The protocol against a server that holds every key and sees everything, for any number of pairs of accounts, each withdrawing and chatting once. |
| M1 to M6 | [TLA+](https://lamport.azurewebsites.net/tla/tla.html) (TLC) | `ledger/` | The money rules every storage layer must keep, in every order of requests, with retries, lost answers and two devices sharing a wallet, in a small world (`Ledger.cfg`). |
| M7 to M9 | Exhaustion | `../lib/examples/exhaustive_proofs.rs` | The Rust code that splits amounts, builds blanks and picks change, for every case in range, one by one. |
| M10, M11 | [Kani](https://model-checking.github.io/kani/) | `../lib/src/proofs.rs` | The Rust code that rounds change and limits withdrawals, for every input in range at once. |

```sh
spec/check.py              # everything: approval, models, Rust proofs
spec/check.py --no-kani    # models only, a minute
spec/mutants.py            # break things on purpose; every break must be caught
spec/status.py             # the rules, approval and last results as JSON (for the admin page)
```

`check.py` and `mutants.py` save their results in `target/spec-status/`, stamped
with a fingerprint of every file in the repo; `status.py` marks them stale once
anything changes.

Needs `proverif` (2.05), Java 11+ with `tla2tools.jar` (`TLA_JAR`, default
`~/.local/share/tla/tla2tools.jar`; `TLA_JAVA` for the java command), and
`cargo install --locked kani-verifier && cargo kani setup`.

## How the models match the code

The ProVerif models follow the code step by step; each step names the Rust
function it stands for. What they take as given, and where that is held:

- Clients only use pinned keys (`lib/src/keyset.rs`; e2e
  `a_server_that_changes_its_keys_is_refused`). Without it P1 fails
  (`mutants.py key-per-account`).
- Voucher messages and blinding come from the wallet seed or the OS, never
  from anything the server sees (`lib/src/blank.rs`, `lib/src/seed.rs`).
  Without it P1 fails (`blinding-from-login-key`).
- Storage gets only hashes (`Spend`, `secret_hash` in `lib/src/server.rs`).
- Each storage call is atomic (the `Backend` contract). The reference server
  holds one lock; a Postgres backend must use one transaction per call.

## Changing a rule

The rules are Tony's. `check.py` fails when anything in this directory or
`lib/src/proofs.rs` differs from `APPROVED`. He reads and approves them on the
Rules page of the Obscurify admin panel (a server started with `RULES_SPEC_DIR`
pointing here), which calls `spec/approve.py --expect FINGERPRINT --yes ...` so
the approval names exactly the text he saw. Otherwise send him
`spec/approve.py --show`, and only after he says yes run
`spec/approve.py --yes "how he said it"`.
