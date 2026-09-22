# Stage 9 — the spend secrets behind the same pair

Stage 7 sealed what the vault writes. Stage 8 sealed what it was told. This
seals what it **signs with**, which is the last large thing on that disk and
the only one where the loss is a client's money rather than their privacy.

## 1. What was still readable

`/etc/gs-wake-spend.env`, `0400`, an `EnvironmentFile` on the agent's unit:

| variable | what it is |
|---|---|
| `GS_BTC_SEED` (+ `GS_BTC_SEED_PASSPHRASE`) | the BIP39 seed. **Spends every deposit address this intake has ever issued.** Stage 8 hid the xpub that *finds* them; this is the key that *takes* them |
| `GS_WALLET_PASSWORD` | opens the spend wallet |
| `GS_FEE_WALLET_PASSWORD` | opens the fee wallet |
| `GS_SWAPKIT_API_KEY` | the aggregator account, which is a name |

It was in the clear for a reason that is real and does not go away: a child
process reads these out of the environment it inherits, and an unattended
signer cannot be asked for a passphrase.

## 2. Why that reason does not force plaintext at rest

`run_child` already **strips every `GS_` variable** and only `env_extra` puts
any back — an allow-list by construction, added when the first secret was
needed. So the children never inherited these from the unit anyway: the
*dispatcher* reads them and hands each step exactly what it needs.

That makes the change small and local. Every read was `os.environ[...]` in
one of six places. They now go through one indirection:

    secret_of(name)   -> the sealed value, else the environment
    has_secret(name)  -> in either, because an EMPTY password is a real
                         answer and `not value` is not the question

and a sealed file is opened right after the wake note, beside the keyfile's
own sealed section, under the same two halves.

## 3. Setup is the recovery habit

The secrets do not exist at pairing time — the operator writes them
afterwards (`OPSEC_SETUP.md` §5), so unlike stage 8 this cannot be sealed
during the ceremony. It is one command, once, at the machine:

    gs_doorbell state-key --key /etc/gs_wake_pi.key        # on the Pi
    gs_wake_agent --seal-secrets <hex> --key /etc/gs_wake_thinkpad.key

This is worth stating plainly, because it resolves the objection that held
this stage back: the concern was that a sealed seed needs the recovery path
to be a *habit* first. It is not a habit the operator has to remember — it
is the habit that installs the feature. They cannot have a sealed seed
without having printed the half once.

**It does not shred the plaintext. It prints the command.** A tool that
sealed a seed and destroyed the only copy of it would be the one failure in
this whole design that costs money rather than privacy, and no read-back
check is worth betting a seed on when the operator can look at the file
themselves. Same rule as `state_close`, one step further out.

## 4. Failing closed, and the one place it is strict

A secrets file that will not open **refuses, and does not fall back to the
environment.** That is the opposite of the compatibility rule everywhere
else here, and deliberately: a box with a sealed file is a box whose
operator believes the seed is protected. Quietly signing from a plaintext
leftover instead would make the seal decorative, and they would never learn.

* No file at all → the environment, exactly as before. Every install from
  before this stage is untouched.
* A file that opens → sealed wins over any leftover, so a forgotten `shred`
  is not a stale signature.
* A file that will not open → `secrets_unreadable`, naming the two causes.
* The allow-list is applied on the way in as well as out: a sealed file is
  still a file, and one swapped for another would otherwise put whatever
  `GS_` variables it liked into every child's environment.
* `_SECRETS.clear()` in `main`'s finally, on every path out — including
  `--dry-run`, `--fee-sweep` and a refusal that keeps the box on, which all
  return through it without powering anything off.

And it adds no way to be stuck that stage 7 did not: if the seal will not
open, the *store* will not open either, under the same key, and the job was
already refused before this stage existed.

## 5. What is left on that disk, stated

* The Monero wallet file — the whole mix graph, encrypted under a password
  that is now sealed. Better than it was, not solved.
* A vault seized **while a job is running** has all three containers open
  in RAM. One job's window, same boundary as stages 7 and 8.
* Both boxes with the Pi's passphrase: everything, as always.
* The marks (`issued_*.json`) are outside every seal on purpose — they are
  the guard against a wiped ledger reissuing an unpaid address. They name no
  address and no client; they say an intake ran here and how many addresses
  it handed out.

## 6. Read again, end to end: what the first pass left half-wired

Every item here was DRIVEN on the build this plan first shipped as, not
reasoned about, and each is now a test in `tests/test_wake_agent.py` and an
anchor in `tests/mutation_sweep.py`.

* **`--seal-secrets` did not read the file the way systemd does.** It
  stripped quote characters off both ends of a line and did nothing else.
  Measured against systemd 255's own `load_env_file`: `"a\"b"` sealed as
  `a\"b` (systemd gives `a"b`), `ends"` as `ends` (systemd keeps the quote),
  `'it''s'` as `it''s` (systemd concatenates: `its`), and it could not see a
  quoted value over two lines, a continuation line, or a bare carriage
  return. A password with a quote or a backslash in it was sealed as a
  DIFFERENT password, the read-back compared that value with itself, and the
  operator was told to shred the original. It is now a port of systemd's
  state machine, fuzzed against `load_env_file` over 200,000 generated files
  with no difference. It refuses, by line number and never by value, what
  systemd refuses (a NUL, a Unicode noncharacter) and the one construct two
  systemd versions read differently (a comment ending in a backslash: v252,
  Debian 12's, swallows the next line; v254 on does not).
* **It sealed under a half it never checked.** The container was sealed
  under whatever hex was typed and read back with the same hex, so a half one
  character off passed, the operator was told to shred, and the next wake
  refused every job `secrets_unreadable` -- with the only copy of the seed on
  that disk under a key nobody holds. The typed half is now checked against
  something the real one opens -- the keyfile's own sealed settings, or the
  record store -- and refused when it does not open it. With nothing sealed
  yet to check against, it seals and says so.
* **It told the operator to shred a seed it had not proven**, and to "check
  the seal works with a real job first" when the job an operator reaches for
  first, a deposit, touches the seed and nothing else. The seed is now proven
  against the pair's xpub before anything is written, and the output names
  the job that exercises each secret it sealed.
* **The hand commands powered the box off under the operator.** `main()` set
  the flag that keeps the machine on only after `--unseal-state` or
  `--seal-secrets` returned, so a keyfile whose half is malformed -- refused
  above each command's own `try` -- powered it off mid-recovery. `--fee-sweep`
  did the same on a wrong half. The flag is set first, and every refusal from
  the fee sweep's half handling keeps the box on.
* **`--fee-sweep --unseal-state <hex>` never swept.** `main()` tested
  `--unseal-state` first, so the exact command every refusal and
  `OPSEC_SETUP.md` name for a sealed box's sweep wrote every sealed record out
  in plaintext and stopped. A stage-8 defect, found here because the driven
  RAM check needed that command to reach the sweep.
* **Two places signed from the environment beside a sealed file.** A wake on
  a keyfile with no half never reached `open_secrets`; a `--fee-sweep` whose
  half did not parse skipped it. Both now refuse -- the wake before the
  doorbell is asked for anything, so the job is not taken. A malformed
  `state_half` is refused there too, instead of after M2.
* **The refusals named the wrong copy.** Every one said to fix the variable
  in the EnvironmentFile; the sealed copy wins, so following that changed
  nothing, and a sealed-away password reported "unset" invited the operator
  to put it back in the clear. They now name the copy the machine read.
* **The idle-boot sweep ran with its password out of reach** and refused it
  "unset". It stands down and says why, and `--seal-secrets` says, while the
  operator is there, that sealing the fee password stops it.

Still true, and stated rather than fixed: **nothing prints the sealed
secrets back.** `--unseal-key` prints the settings; there is no counterpart
for the seed. That is deliberate in the sense that the seal is not a backup
and the tool says so -- but it means a box whose plaintext has been shredded
holds its seed only sealed, and it dies with the keyfile. Keep the seed words
where you keep them.
