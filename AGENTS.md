# Rules for anyone — human or agent — changing this repository

These are not style preferences. Each one is here because breaking it has
already cost something in this codebase, and the cost is recorded beside the
fix. Read all of them before you change a line.

---

## 1. KERCKHOFFS'S PRINCIPLE. This is rule one and it outranks the rest.

**Assume the adversary has read every line of this repository.** They have
the source, the constants, the protocol, the file formats, the port numbers,
the wake schedule and the rate limits. They have this file.

A security property may rest on exactly one thing: **a secret** — a key, a
passphrase, a pairing secret. It may never rest on:

- a constant an attacker would have to guess, that is in the source;
- a format, a magic value, a filename or a path used as a barrier;
- a check that only works because somebody "would not think to try it";
- obscurity standing in for authentication or authorisation;
- a limit whose value is public and therefore plannable around.

When you add a defence, state in the comment **which secret it rests on**. If
the honest answer is "it rests on them not knowing", it is not a defence and
must not be written as one. Say so plainly instead — a hazard the operator
can see is worth more than a guarantee that is not one.

The inverse is also a defect: a comment that CLAIMS a key-based guarantee
over a mechanism that is actually obscurity. Several have been found here.

## 2. Functionality is not a separate concern from security.

A feature that silently does nothing is a defect of the same rank as a leak.
The recurring shapes in this repository, each found more than once:

- **the silent zero** — a fee, a limit or a count that is quietly nothing,
  with no way for the operator to learn it;
- **declared in one place, never wired to the thing that runs** — a field
  with a reader, a renderer, a wire format and a test suite, and no writer;
- **the guard on one side of a boundary only** — a value validated where it
  is produced and not where it is consumed, or the reverse;
- **the refusal that arrives after the money has moved** — a check that is
  correct but placed after the irreversible step, when the same check earlier
  would have cost nothing;
- **one state, two sentences, decided twice** — two messages about the same
  event whose conditions were written separately and can disagree. The
  withdraw chain told the operator "Starting the next one now" and then
  "Stopping after 6 in a row", seconds apart, because one line tested
  `more_left` and the other tested `more_left AND under the cap`. Decide it
  once, name it, and let both readers use the name;
- **the number on screen that is not an answer** — a prompt that prints
  numbers the step it belongs to will not accept. This has bitten twice in
  the depth menu: first with the wire's key beside the hop count (so "3" meant
  twenty hops), then with the runtime first (so 6, 9 and 13 became the salient
  numbers and none is a valid answer). **Whatever leads a row is read as the
  answer.** And a refusal at such a step must not throw away work the operator
  has already done — re-ask instead.

## 3. Do not trust the comments, the tests, or the docs. Including these.

The comments here are long and narrate past bugs. Some have been found to
describe fixes that were never made, or to record a design that was
considered and REJECTED as though it had shipped — `USAGE_FEE_ACCOUNT_LABEL`
is the example, documented as a live protection that never existed.

A test can be green and prove nothing: it can assert against a stale fixture,
reimplement the logic it means to pin instead of calling it, crash before its
own checks run, or be structurally unable to see the defect. Every claim gets
verified against the shipped code. Run it if you can.

Two failures of this kind are worth naming because both were written HERE,
this repository's own tests, while fixing something else:

- **comparing a derivation against itself.** `depth_hours(d) ==
  round(WITHDRAW_DEPTHS[d][1] / 3600)` passes for a hardcoded
  `{1: 6, 2: 9, 3: 13}`, because that dict returns today's answers. To pin
  "derived, not written down", MOVE the source table and check the function
  follows. `tests/mutation_sweep.py` reported the first form as SURVIVED.
- **substring-matching a small number against text that carries random
  digits.** A check that the confirm no longer names the arrival count
  searched for `"5"` in a message ending in a randomly drawn `a + b = ?`.
  Green in the tree, red the first time it ran on a copy. That is a coin,
  not a test.

## 4. Think in failure scenarios, not in review generalities.

A finding is: **concrete inputs or state → what actually happens → why that
is wrong.** If the scenario cannot be constructed, there is no finding. If it
can, drive it — this repository's real defects were found by running the code
with hostile inputs, not by reading it.

## 5. Read end to end.

Sampling a file finds what you already suspected. Several defects here sat in
the parts that look boring: a `print()` on a unit with `StandardOutput=null`,
a loop variable clobbering a module-level fixture, a test block appended
after `sys.exit`.

## 6. The transcript is readable and the card is seizable.

Assume the Telegram chat is read by somebody who is not the operator, and
that the Pi's SD card is in someone else's hands. Nothing may reach either
that names a machine, a tool, an address, an amount, a memo, or the shape of
the arrangement. The banned-word scan enforces part of this; the scan reads
string literals in `gs_telegram_pager` only, so **chat text that lives in
another file is still chat text** and has escaped twice.

## 7. Refuse before the irreversible step, or waive — never abort after.

Once BTC has settled through the swap, the XMR is on an address a public
`OP_RETURN` names. A refusal there strands it. Gates belong before the
deposit instructions exist, where "nothing has been spent" is true of the
deposit as well as of the wallet.

## 8. One operator. One wallet. One person.

There is a single wallet behind this and a withdrawal does not ask who is
asking. The pager refuses more than one allowlisted person and there is
deliberately no override: consent from one party to a loss that falls on a
second is not consent.
