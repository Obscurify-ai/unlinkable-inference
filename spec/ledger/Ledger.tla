---------------------------- MODULE Ledger ----------------------------
(* The money rules every server backend must keep (lib/src/server.rs, trait
   `Backend`), as a state machine. TLC tries every order of every request,
   including retries after a lost answer and two devices holding copies of
   the same vouchers, and checks the invariants below in every state.

   Amounts are whole units here. Turning nanodollar balances into millicents
   (rounded up) and millicents into voucher values is proved separately, on
   the Rust code itself (lib/src/proofs.rs). *)
EXTENDS Naturals, Integers, FiniteSets, TLC

CONSTANTS
  Start,      \* the account's balance at the start (paid money)
  Promo,      \* promotional credit the account starts with, already in vouchers
  Ids,        \* voucher slots (bounds the model)
  Secrets,    \* session secrets clients may pick
  Digests,    \* request digests clients may send (same blanks = same digest)
  Sizes,      \* withdrawal sizes allowed
  MaxCost     \* the most one model request costs

Families == {"paid", "promo"}

VARIABLES
  acct,       \* the account's balance
  issued,     \* id -> [val, fam] for every voucher the server signed
  spent,      \* ids spent (the server keeps their hashes)
  sessions,   \* secret -> session record
  answers,    \* digest -> the voucher ids a withdraw or exchange gave back
  wallet,     \* ids the devices hold (copies shared by every device)
  charged,    \* fam -> what requests cost, in total
  forgiven    \* fam -> what the server let sessions overdraw and wrote off

vars == <<acct, issued, spent, sessions, answers, wallet, charged, forgiven>>

NoSession == [st |-> "none", bal |-> 0, fam |-> "paid", digest |-> {}, closeDigest |-> "none", change |-> {}]

RECURSIVE SumSet(_, _)
SumSet(S, f) == IF S = {} THEN 0 ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumSet(S \ {x}, f)

Val(S) == SumSet(S, [i \in S |-> issued[i].val])
FamOf(S) == {issued[i].fam : i \in S}
Unused == {i \in Ids : i \notin DOMAIN issued}
Fresh == CHOOSE i \in Unused : \A j \in Unused : i <= j

\* Sign a voucher worth v of family f (v > 0); nothing for 0.
Mint(v, f) == IF v = 0 THEN [ids |-> {}, iss |-> issued]
              ELSE [ids |-> {Fresh}, iss |-> [x \in DOMAIN issued \cup {Fresh} |->
                                              IF x = Fresh THEN [val |-> v, fam |-> f] ELSE issued[x]]]

Init ==
  /\ acct = Start
  /\ issued = IF Promo = 0 THEN [x \in {} |-> 0] ELSE [x \in {1} |-> [val |-> Promo, fam |-> "promo"]]
  /\ spent = {}
  /\ sessions = [s \in Secrets |-> NoSession]
  /\ answers = [d \in {} |-> {}]
  /\ wallet = DOMAIN issued
  /\ charged = [f \in Families |-> 0]
  /\ forgiven = [f \in Families |-> 0]

(* POST /u/withdraw. A repeat of a digest gets its stored answer and moves no
   money; the answer may be lost on the way (the device keeps nothing). *)
Withdraw(d, amt, delivered) ==
  /\ d \notin DOMAIN answers
  /\ amt <= acct
  /\ Unused # {}
  /\ LET m == Mint(amt, "paid") IN
     /\ issued' = m.iss
     /\ answers' = answers @@ (d :> m.ids)
     /\ acct' = acct - amt
     /\ wallet' = IF delivered THEN wallet \cup m.ids ELSE wallet
  /\ UNCHANGED <<spent, sessions, charged, forgiven>>

\* Any repeated withdraw or exchange: the stored answer, nothing else changes.
Repeat(d) ==
  /\ d \in DOMAIN answers
  /\ wallet' = wallet \cup answers[d]
  /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>

(* POST /u/sessions. All the vouchers or none; a secret in use is a retry
   only with exactly the vouchers that opened it. *)
Open(s, vs, delivered) ==
  /\ vs # {} /\ vs \subseteq wallet /\ Cardinality(FamOf(vs)) = 1
  /\ IF sessions[s].st # "none" THEN
       \* retry (same vouchers) or someone else's secret: nothing moves
       /\ wallet' = IF sessions[s].digest = vs THEN wallet \ vs ELSE wallet
       /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>
     ELSE IF vs \cap spent # {} THEN
       \* 409: nothing spent; the device drops the ones that were
       /\ wallet' = wallet \ (vs \cap spent)
       /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>
     ELSE
       /\ spent' = spent \cup vs
       /\ sessions' = [sessions EXCEPT ![s] = [NoSession EXCEPT !.st = "open", !.bal = Val(vs),
                                               !.fam = CHOOSE f \in FamOf(vs) : TRUE, !.digest = vs]]
       /\ wallet' = IF delivered THEN wallet \ vs ELSE wallet
       /\ UNCHANGED <<acct, issued, answers, charged, forgiven>>

(* POST /u/sessions/topup: an open session of the same family, all or none. *)
Topup(s, vs) ==
  /\ vs # {} /\ vs \subseteq wallet /\ FamOf(vs) = {sessions[s].fam}
  /\ sessions[s].st = "open"
  /\ IF vs \cap spent # {} THEN
       /\ wallet' = wallet \ (vs \cap spent)
       /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>
     ELSE
       /\ spent' = spent \cup vs
       /\ sessions' = [sessions EXCEPT ![s].bal = @ + Val(vs)]
       /\ wallet' = wallet \ vs
       /\ UNCHANGED <<acct, issued, answers, charged, forgiven>>

(* A model request. Refused at a balance of 0 or less; one that costs more
   than is left overdraws (the reply was already streamed). *)
Charge(s, cost) ==
  /\ sessions[s].st = "open" /\ sessions[s].bal > 0
  /\ sessions' = [sessions EXCEPT ![s].bal = @ - cost]
  /\ charged' = [charged EXCEPT ![sessions[s].fam] = @ + cost]
  /\ UNCHANGED <<acct, issued, spent, answers, wallet, forgiven>>

(* POST /u/sessions/close: change for the whole balance (none for a
   negative one, which the server writes off), in the session's family. A
   repeat with the same blanks gets the same change; other blanks get 410. *)
Close(s, d, delivered) ==
  /\ sessions[s].st # "none"
  /\ IF sessions[s].st = "closed" THEN
       /\ wallet' = IF sessions[s].closeDigest = d THEN wallet \cup sessions[s].change ELSE wallet
       /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>
     ELSE
       /\ (sessions[s].bal <= 0 \/ Unused # {})
       /\ LET b == sessions[s].bal
              f == sessions[s].fam
              m == Mint(IF b > 0 THEN b ELSE 0, f) IN
          /\ issued' = m.iss
          /\ sessions' = [sessions EXCEPT ![s].st = "closed", ![s].bal = 0,
                                          ![s].closeDigest = d, ![s].change = m.ids]
          /\ forgiven' = [forgiven EXCEPT ![f] = @ + (IF b < 0 THEN -b ELSE 0)]
          /\ wallet' = IF delivered THEN wallet \cup m.ids ELSE wallet
          /\ UNCHANGED <<acct, spent, answers, charged>>

(* POST /u/exchange: vouchers in, vouchers worth the same out, same family. *)
Exchange(d, vs, delivered) ==
  /\ d \notin DOMAIN answers
  /\ vs # {} /\ vs \subseteq wallet /\ Cardinality(FamOf(vs)) = 1
  /\ IF vs \cap spent # {} THEN
       /\ wallet' = wallet \ (vs \cap spent)
       /\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>
     ELSE
       /\ Unused # {}
       /\ LET m == Mint(Val(vs), CHOOSE f \in FamOf(vs) : TRUE) IN
          /\ issued' = m.iss
          /\ spent' = spent \cup vs
          /\ answers' = answers @@ (d :> m.ids)
          /\ wallet' = IF delivered THEN (wallet \ vs) \cup m.ids ELSE wallet
          /\ UNCHANGED <<acct, sessions, charged, forgiven>>

\* A device loses its copy of a voucher it holds (another device keeps one).
Next ==
  \/ \E d \in Digests, a \in Sizes, dl \in BOOLEAN : Withdraw(d, a, dl)
  \/ \E d \in Digests : Repeat(d)
  \/ \E s \in Secrets, vs \in SUBSET wallet, dl \in BOOLEAN : Open(s, vs, dl)
  \/ \E s \in Secrets, vs \in SUBSET wallet : Topup(s, vs)
  \/ \E s \in Secrets, c \in 1..MaxCost : Charge(s, c)
  \/ \E s \in Secrets, d \in Digests, dl \in BOOLEAN : Close(s, d, dl)
  \/ \E d \in Digests, vs \in SUBSET wallet, dl \in BOOLEAN : Exchange(d, vs, dl)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* The rules. *)

OpenBal(f) == SumSet({s \in Secrets : sessions[s].st = "open" /\ sessions[s].fam = f},
                     [s \in Secrets |-> sessions[s].bal])
UnspentVal(f) == Val({i \in DOMAIN issued \ spent : issued[i].fam = f})

\* M1. Nothing is made or lost: per family, what the customer holds (account,
\* unspent vouchers, open sessions) plus what requests cost equals what came
\* in, plus what the server wrote off.
Conservation ==
  /\ acct + UnspentVal("paid") + OpenBal("paid") + charged["paid"] = Start + forgiven["paid"]
  /\ UnspentVal("promo") + OpenBal("promo") + charged["promo"] = Promo + forgiven["promo"]

\* M2. The customer never pays more than requests cost: everything they hold
\* is worth at least what came in minus what they used.
NeverOvercharged ==
  \A f \in Families : (IF f = "paid" THEN acct ELSE 0) + UnspentVal(f) + OpenBal(f)
                        >= (IF f = "paid" THEN Start ELSE Promo) - charged[f]

\* M3. Nothing can be spent twice and nothing unsigned can be spent.
SpentWereIssued == spent \subseteq DOMAIN issued

\* M4. The account never goes below zero.
AccountNonNegative == acct >= 0

\* M5. Every voucher the server ever signed can be had again by repeating the
\* request that made it, so a lost answer never loses money.
Recoverable ==
  \A i \in DOMAIN issued :
    \/ (i = 1 /\ Promo > 0)
    \/ \E d \in DOMAIN answers : i \in answers[d]
    \/ \E s \in Secrets : i \in sessions[s].change

\* M6. Change and exchanges stay in the family that paid: promo never becomes paid.
\* (Covered by Conservation per family; stated alone for the rules list.)
FamiliesApart == \A s \in Secrets : sessions[s].st # "none" => FamOf(sessions[s].digest) = {sessions[s].fam}

=============================================================================
