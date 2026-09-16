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
