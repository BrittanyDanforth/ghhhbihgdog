# Stage 7 — the vault's records are sealed to the PAIR, not to the vault

The host-privacy pass found one hole that dwarfs the rest, and it is not a
leak in the ordinary sense: it is the design working as intended.

The vault's disk auto-unlocks. It has to — `OPSEC_SETUP.md` §5 is a machine
that is **off by default** and boots when the Pi wakes it, with nobody
present. A disk that asks for a passphrase cannot do that. So the disk
decrypts itself for whoever powers the machine on, and full-disk encryption
buys nothing against a seizure.

What that yields today, in the clear, from one seized laptop:

| file | what it holds |
|---|---|
| `gs_wake_handles.json` | every handle: its owner token, its `btc_index` (→ the deposit address under the keyfile's xpub), its (account, subaddress), whether it was paid out |
| `thor_pairs_<h>.json` | the deposit address, the amount, and the memo — which names the client's XMR address in full |
| `wallet_<hex>.json` | the XMR subaddress each deposit lands on |
| `btc_forward_<h>.json` + its rotated chain | the client's own payment outpoints, the txid of the forward, the ThorChain vault it paid, the memo again, and the signed bytes while they are kept |
| `gs_wake_state.json` | a 24-hour wake timetable, and the last 200 job ids |

That is the whole intake since the last hand-run wipe: who paid what, when,
and where it went. §1 of `OPSEC_SETUP.md` scores the ThinkPad row on "they
can watch incoming", and this is the row that makes it generous.

## 1. The one property that makes a fix possible

**Nothing in that directory is read before the Pi has authenticated a wake
note.** Measured, not assumed:

* `load_key` reads the keyfile, not the directory.
* `preflight` reads the inhibit file, the lock, the deadman, the removable
  devices, the resource sentinel, `wipe_covers` and Tor. No member.
* `_idle_boot_sweep` (a hand power-on, or a stranger's magic packet) runs the
  fee sweep, which reads the keyfile and the wallet RPC — no member.
* `load_state`, `_load_ledger`, the slips, the bundles and the plans are all
  touched inside `_run_validated`, which runs **after** M2 is opened,
  authenticated and validated.

So the vault does not need to be able to read its own records at boot. It
needs to read them during a job the Pi asked for — and the Pi is a second
machine, with a passphrase-sealed keyfile, that the same adversary does not
necessarily have.

## 2. The shape

One sealed container, `state.sealed`, in the artifact directory. Its key is
derived from two halves:

    state_key = blake2b(vault_half || pi_half, key=salt, person="gs-state-v1")

BLAKE2b, not HKDF, and the difference is not cosmetic: it is one primitive
out of `hashlib`, keyed and personalised by the standard's own parameters,
with no construction of ours around it. The rule for money in this tree is
no hand-rolled crypto, and a two-line KDF assembled from HMAC would have
been exactly that.

* `vault_half` — 32 random bytes written into the vault's keyfile at
  pairing. Plaintext on the vault, like the rest of that file.
* `pi_half` — `blake2b(b"gs-state-half-v1", key=pi_secret)`, derived by the doorbell
  from the secret already in its **sealed** keyfile. Never stored on the
  vault, never on the wire in the clear: it rides inside M2, which is boxed
  to the vault's per-boot ephemeral key.

Neither half is useful alone. The salt is per-store, in the container's
plaintext header.

| seized | yields |
|---|---|
| the vault alone | `state.sealed` and `vault_half`. Ciphertext. |
| the Pi alone | a sealed keyfile; with its passphrase, `pi_half` — and no store to open |
| both, with the Pi's passphrase | everything (this was already total: that pair can forge a wake note) |

**One container, not one file each.** Per-file sealing would leave the file
NAMES on the disk, and the names are `thor_pairs_<handle>`,
`btc_forward_<handle>`, `wallet_<hex>` — the deposit count, the handles and
the number of forwards each had, which is most of what the sealing is for.

## 3. The lifecycle

1. **Open** — first thing in `_run_validated`, before `load_state`. Decrypt
   `state.sealed`, write each member out at 0600.
2. **Run** — unchanged. Every path, and every child process, sees exactly
   the directory it saw before.
3. **Close** — in `main`'s `finally`, before `power_off`. Pack the members,
   write `state.sealed.new`, fsync it, **re-open it to prove it opens**,
   `os.replace` it into place, then `secure_delete` each plaintext member.

### What is sealed

`gs_wake_handles.json`, `gs_wake_state.json`, `thor_pairs_*.json`,
`wallet_*.json`, `btc_forward_*.json` (and the rotated `.N.json`), and
`gs_wake_status.json`.

The status file was in the list below, as "transient, already unlinked
after one read", until the self-doubt pass drove the crash paths. That
sentence is true of every path that *reaches* the unlink, and a killed
probe or a power cut does not — what it leaves is `unlocked` and `total`
as exact decimals, which is how much of somebody's swap has arrived, to
the piconero. The forward's own status file was already being swept in by
the `btc_forward_*.json` glob, so the pair of them disagreed. Sealing it
changes no behaviour: both jobs that read it (`swap_status`, `watch`)
unlink it at their **start**, so a member restored out of the store is
cleared before anything can mistake it for this run's answer.

### What is not, and why

* `gs_wake_job.log` — written continuously by children, and the fix for it
  is deletion, not encryption: it is shredded at the end of a clean run.
* `integrity_chain.log` — a hash chain whose whole value is that it is
  append-only and readable for an audit. It already carries no address, no
  amount and (since the host-privacy pass) no version. Sealing it would make
  the audit need the Pi.
* `.gs_wake_inhibit`, `.ghostspiral.lock` — marks and a lock. They hold no
  figure and no name; what they say is "a run is in progress here", which
  the presence of the directory says anyway.
* `wallet_feesweep.json` — written and retired inside one sweep, which may
  run on a boot that has no half (an idle boot). It holds the operator's own
  fee subaddress, not a client's.

## 4. Failing closed, and failing safe — they point opposite ways here

* **A store that will not open → REFUSE the job.** Running with an empty
  ledger would re-issue an address that is already someone's, and lose the
  owner→accounts map. The refusal names the two causes (a re-pairing since
  the store was written; a corrupt file) and the recovery command.
* **A close that fails → LEAVE THE PLAINTEXT.** The money's bookkeeping
  survives a failed seal; it does not survive a plaintext shred whose
  ciphertext was never written. The kind goes on the chain, the operator is
  told, and the next wake seals what is there.
* **A crash mid-job → plaintext stays**, exactly as today. The next wake
  seals it after M2.
* **The plaintext is deleted only after the new container has been read
  back** and proven to open with the same key.

## 5. Recovery, which is the operator's real risk

Losing `pi_half` means the records cannot be opened. The money is not lost
(the seed and the wallets are elsewhere) but the bookkeeping is: open
deposits could not be paid out. Two commands exist for it, and both are
documented beside the LUKS USB in §1:

    gs_doorbell state-key --key /etc/gs_wake_pi.key   # prints pi_half (asks the passphrase)
    gs_wake_agent --unseal-state <hex> --key ...      # opens the store, by hand, at the machine

**A re-pairing makes an existing store unreadable**, because `pi_secret`
changes. The pairing says so before it writes anything, and the door-coming-
in wipe recipe already shreds the store with the rest.

## 6. Compatibility: additive, and it turns on at the next pairing

A keyfile with no `state_half` is a pairing from before this stage. The
vault then runs exactly as it does today, unsealed, and says so once on the
chain (`state_unsealed`). Nothing breaks for an install that does not
re-pair; nothing is silently downgraded for one that does, because a vault
whose keyfile HAS a half refuses a note that carries none.

`WIRE_VERSION` goes to 10: M2 gains a field, and a half-upgraded pair must
fail loudly rather than mysteriously.

## 7. What this does not fix, stated

* The BTC seed and the wallet passwords are in the agent unit's environment
  file, in the clear, and the vault's own keyfile still holds the account
  **xpub** — which is every deposit address this intake has ever issued, so
  a seizure still attributes every past deposit on the public chain to this
  box. §1 says it.

  An earlier draft of this line said "no arrangement of keys on one box
  changes that", and that is wrong in the one way that matters: these are
  not read before M2 either, so the same two halves that seal the records
  can seal them. It is not done here because it is a bigger change with a
  worse failure mode (a seed nobody can open is a client's money, not a
  client's bookkeeping) and it needs the recovery path in §5 to be a habit
  first. It is the next thing, not an impossibility.
* The Monero wallet file is the whole mix graph and is not touched here.
* A vault seized **while a job is running** has the plaintext and the key in
  RAM. The window is one job.
* An adversary with both boxes and the Pi's passphrase has everything, and
  had everything before this stage too.
