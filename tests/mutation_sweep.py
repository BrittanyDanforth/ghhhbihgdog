#!/usr/bin/env python3
"""MUTATION SWEEP: break each guarantee on purpose, and see if anything notices.

A green suite proves nothing on its own. This breaks ONE guarantee at a time,
in the way a plausible refactor would, and reports whether any test turns red.
Run it after changing anything in the --split / entry-set / exit machinery:

    python3 tests/mutation_sweep.py          # all mutations
    python3 tests/mutation_sweep.py 4 11     # just these two

THIS HARNESS HAS LIED IN BOTH DIRECTIONS, and both guards below exist because
of it. Neither is theoretical; each cost a wrong conclusion during the audit
that produced this file.

  * IT REPORTED GREEN ON A MUTATION THAT NEVER REACHED DISK. Two sweeps once
    shared a scratch directory and one's cleanup wiped the other mid-run, so
    suites ran UNMUTATED and every result was meaningless -- which produced a
    confident, false finding that a real invariant was untested. Hence: a
    unique mktemp per mutation, serial execution, and a grep -qF that PROVES
    the replacement is on disk before any result is believed.

  * IT REPORTED SURVIVED FOR GUARANTEES THAT WERE TESTED. Four mutations named
    the wrong suite -- the tests existed and passed, in a file the mutation
    never ran -- and two anchored on the integrity_log() line ABOVE a guard, so
    the sys.exit() below still fired and the mutation changed no behaviour at
    all. That is the more expensive direction: green makes you complacent,
    SURVIVED makes you rewrite working code.

  * A SUITE THAT CRASHES IS NOT A CATCH. A mutation that makes a test file die
    with a traceback prints no RESULT line, and a crashed suite proves nothing
    about its checks. Those score NO-RESULT, never CAUGHT -- and the right fix
    is usually in the TEST (make it fail with its own words instead of dying).

  * SKIP IS NOT A PASS EITHER. An anchor that matches zero or several times
    means the mutation did not apply, so that guarantee went UNSWEPT. Re-anchor
    it; do not read the tally as coverage.

Each entry is (name, file, find, replace, [suites that must go red]).
"""
import os, re, shutil, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, file, find, replace, [suites that must go red])
MUTATIONS = [
 ("entry set mints ONE address however many chunks", "GhostSpiral",
  "    for _ in range(max(1, int(n))):",
  "    for _ in range(1):",
  ["test_dag_entry", "test_send_gates"]),

 ("every chunk quoted to the FIRST destination (the original G5)", "GhostSpiral",
  "        chunk_dest = xmr_dests[i]",
  "        chunk_dest = xmr_dests[0]",
  ["test_send_gates"]),

 ("the per-chunk/per-dest count mismatch is not refused", "GhostSpiral",
  "    if len(xmr_dests) != len(chunks):",
  "    if False:",
  ["test_dag_entry", "test_send_gates"]),

 ("duplicate swap destinations allowed", "GhostSpiral",
  "    if len(set(xmr_dests)) != len(xmr_dests):",
  "    if False:",
  ["test_dag_entry", "test_send_gates"]),

 ("all veils pay ONE shared carrier", "GhostSpiral",
  "    if len(set(_caddrs)) != len(_caddrs) or len(set(_caccts)) != len(_caccts):",
  "    if False:",
  ["test_dag_entry"]),

 ("duplicate entry ADDRESS not refused", "GhostSpiral",
  "    if len(set(_addrs)) != len(_addrs):",
  "    if False:",
  ["test_dag_entry"]),

 ("duplicate entry ACCOUNT not refused", "GhostSpiral",
  "    _accts = [c for _, c, _ in entries]\n    if len(set(_accts)) != len(_accts):",
  "    _accts = [c for _, c, _ in entries]\n    if False:",
  ["test_dag_entry"]),

 ("ONE distribution over every destination (the convergence)", "GhostSpiral",
  "        for _si, (_src_addr, _src_acct, _src_idx) in enumerate(SPEND_SOURCES):",
  "        for _si, (_src_addr, _src_acct, _src_idx) in enumerate(SPEND_SOURCES[:1]):",
  ["test_dag_entry"]),

 ("only the first carrier's change is a change location", "GhostSpiral",
  "        change_accounts = [a for _d, a, _i in SPEND_SOURCES]",
  "        change_accounts = [SPEND_SOURCES[0][1]]",
  ["test_dag_entry"]),

 ("the arrival gate watches ONE entry address", "GhostSpiral",
  "    for acct, idx in pairs:",
  "    for acct, idx in pairs[:1]:",
  ["test_swap_arrival"]),

 ("every slice's budget is the WHOLE usable", "GhostSpiral",
  "    slice_usable = [usable * (u / total) for u in entry_unlocked]",
  "    slice_usable = [usable for u in entry_unlocked]",
  ["test_dag_entry"]),

 ("DAG hops may cross swap chunks", "GhostSpiral",
  "        _groups = _slices + ([_residual] if _residual else [])",
  "        _groups = [list(mix_targets)]",
  ["test_dag_entry"]),

 ("the BTC chunks are all equal again", "GhostSpiral",
  "    weights = [Decimal(1) + SPLIT_JITTER",
  "    weights = [Decimal(1) + Decimal(0) * SPLIT_JITTER",
  ["test_dag_entry", "test_send_gates"]),

 ("a sub-satoshi --btc-amount is accepted", "GhostSpiral",
  "    if amt != amt.quantize(SATOSHI_BTC):",
  "    if False:",
  ["test_dag_entry"]),

 ("--split with --peel is allowed at parse time", "GhostSpiral",
  '    if n > 1 and getattr(args, "peel", False):',
  "    if False:",
  ["test_dag_entry"]),

 ("the clean-exit message tests the container, not the counts", "GhostSpiral",
  "        elif _relayed and not (_held_entry or _held_change):",
  "        elif _relayed and not _held:",
  ["test_exit_withdraw"]),

 ("an unfunded chunk is not dropped", "GhostSpiral",
  "    funded = [(e, u) for e, u in zip(entry_set, entry_unlocked) if u > DUST_XMR]",
  "    funded = [(e, u) for e, u in zip(entry_set, entry_unlocked)]",
  ["test_dag_entry"]),

 # Was a COIN FLIP before the construction replaced the nudge loop: the check
 # drew 120 random splits and hoped one collided, so it reported SURVIVED on
 # one sweep and CAUGHT on the next. It is deterministic now -- _FlatRNG makes
 # every weight identical, so the repair has to do its whole job.
 ("two BTC chunks may be equal", "GhostSpiral",
  "    if _excess == 0:\n        amounts = [SATOSHI_BTC * _v for _v in _sat]",
  "    if False:\n        amounts = [SATOSHI_BTC * _v for _v in _sat]",
  ["test_dag_entry"]),

 # One give-back pass instead of sweeping to convergence: stalls whenever the
 # staircase is already tight, which is exactly the small-total case.
 ("the distinctness give-back runs once instead of to convergence",
  "GhostSpiral",
  "    while _excess > 0:\n        _moved = False",
  "    while _excess > 0 and False:\n        _moved = False",
  ["test_dag_entry"]),

 # n satoshis, not 1+2+...+n: accepts totals whose only split is repeats.
 ("--btc-amount is bounded at n satoshis, not n distinct ones", "GhostSpiral",
  "    _min_sat = n * (n + 1) // 2",
  "    _min_sat = n",
  ["test_dag_entry"]),

 ("the console split bound drifts from gs_common", "gs_console",
  '    "split":        ("int", (1, 8)),',
  '    "split":        ("int", (1, 20)),',
  ["test_console"]),

 ("only the FIRST entry pair is verified against the wallet", "GhostSpiral",
  "    for _pos, entry_addr in enumerate(entry_addr_list):",
  "    for _pos, entry_addr in enumerate(entry_addr_list[:1]):",
  ["test_units"]),

 ("the exit holds only the FIRST entry address", "GhostSpiral",
  "    return [addr_index[a] for a in _addrs if a in addr_index]",
  "    return [addr_index[a] for a in _addrs[:1] if a in addr_index]",
  ["test_dag_entry", "test_exit_withdraw"]),

 ("held outputs are all reported as ENTRY", "GhostSpiral",
  '            _held_kinds["entry" if _is_entry else "change"] += 1',
  '            _held_kinds["entry"] += 1',
  ["test_exit_withdraw"]),

 ("a chunk with no destinations is silently dropped", "GhostSpiral",
  "    if any(not sl for sl in slices):",
  "    if False:",
  ["test_dag_entry"]),

 ("--split has no upper bound", "GhostSpiral",
  "    if n > MAX_SPLIT:\n        integrity_log(\"stage0\", \"split_too_large\")",
  "    if False:\n        integrity_log(\"stage0\", \"split_too_large\")",
  ["test_dag_entry"]),

 ("JoinMarket's UTXO count is unbounded", "GhostSpiral",
  "        if n > MAX_SPLIT:",
  "        if False:",
  ["test_dag_entry"]),

 ("a plan carries tx_extra again (the inert field, re-added)", "GhostSpiral",
  '            "dst": addr,\n            "sweep": True,',
  '            "dst": addr,\n            "extra": secure_hex(16),\n            "sweep": True,',
  ["test_dag_entry", "test_exit_withdraw"]),

 ("the veil delay is a fixed value, not jittered", "GhostSpiral",
  '            "delay": hop_delay(delay_window),\n        })\n        carriers.append',
  '            "delay": (delay_window or DEFAULT_HOP_DELAY)[0],\n        })\n        carriers.append',
  ["test_dag_entry"]),

 ("--btc-amount positivity is not enforced", "GhostSpiral",
  "    if amt <= 0:\n        integrity_log(\"stage0\", \"btc_amount_not_positive\")",
  "    if False:\n        integrity_log(\"stage0\", \"btc_amount_not_positive\")",
  ["test_units"]),

 ("the DAG round is costed as the confirm wait only", "GhostSpiral",
  "        secs += confirm + mean * mix_outputs",
  "        secs += confirm",
  ["test_dag_entry"]),

 ("the runtime estimate ignores a custom --hop-delay", "GhostSpiral",
  "    lo, hi = delay_window or DEFAULT_HOP_DELAY",
  "    lo, hi = DEFAULT_HOP_DELAY",
  ["test_dag_entry"]),

 ("--deep silently buys no transactions", "GhostSpiral",
  "                          f\"(min {MIN_DEEP}). It does NOT add hop rounds: \"",
  "                          f\"(min {MIN_DEEP}). Depth multiplier. \"",
  ["test_dag_entry"]),

 ("the signer accepts a key-image plan entry", "airgap_tx_signer",
  '        if tx.get("key_image") is not None or tx.get("sweep_single"):',
  "        if False:",
  ["test_signer_schema"]),

 ("the DAG may hop back to a non-first entry address", "GhostSpiral",
  "        others = [b for b in subs if b != a and b not in _entry_set]",
  "        others = [b for b in subs if b != a and b not in list(_entry_set)[:1]]",
  ["test_dag_entry", "test_units"]),

 ("the holdings report names only the first entry account", "GhostSpiral",
  "    _entry_funded = sorted(_entry_accts & {a for a, _ in funded})",
  "    _entry_funded = sorted(list(_entry_accts)[:1])[:0]",
  ["test_dag_entry", "test_units"]),

 ("manual mode prints one --dests for every chunk", "GhostSpiral",
  '                      + " ".join(scrub_address(_a) for _a in ENTRY_ADDRS)',
  '                      + scrub_address(ENTRY_ADDRS[0])',
  ["test_send_gates"]),

 # The exit hold is the LAST thing standing between a swap chunk that landed
 # late and a one-hop sweep to --exit-to from the address the OP_RETURN memo
 # names in public. Narrowing it to the funded subset is the obvious edit --
 # every other consumer wants the funded one -- and it fails silently: the run
 # reports success.
 ("the exit holds only the chunks that ARRIVED, not the full entry set",
  "GhostSpiral",
  "                                 exit_hold=_exit_hold_list(args, addr_index,\n"
  "                                                           ENTRY_ADDRS))",
  "                                 exit_hold=_exit_hold_list(args, addr_index,\n"
  "                                                           [_e[0] for _e in ENTRY_SET_FUNDED]))",
  ["test_split_partial"]),

 # The amounts must follow the ADDRESS. Reverting to the flat concatenation
 # re-couples them to split_by_weight returning contiguous slices in order --
 # measured, a carrier holding 0.75 XMR is then told to pay 3.12.
 ("the fan-out amounts are matched to destinations BY LIST POSITION",
  "GhostSpiral",
  "    amounts = [by_addr[a] for a in fanout_dests]",
  "    amounts = [by_addr[a] for sl in slices for a in sl]",
  ["test_dag_entry"]),

 # A wipe that could not run must say so; a file that was never created must
 # not be reported as one still on disk.
 ("a failed wipe of the change-sweep plan is silent again", "GhostSpiral",
  '        secure_delete_or_warn(path, "the change-sweep plan (its destination)")',
  "        pass",
  ["test_units"]),

 ("a path that never existed is reported as a FAILED wipe", "gs_common.py",
  "    if not os.path.lexists(path):\n        return True",
  "    if False:\n        return True",
  ["test_shmwipe"]),

 # The carrier timeout is the ONLY early return in _stage5_run, so it is the
 # one failure where no exit runs and the money simply stays where it is. What
 # the operator is told here is the whole recovery.
 ("the carrier timeout tells the operator to re-run (which strands it)",
  "GhostSpiral",
  '                print(f"      DO NOT simply re-run: this run\'s carriers are "',
  '                print("      Re-run once it confirms."); print(f"      IGNORED: "',
  ["test_units"]),

 ("the carrier timeout names only the carrier that FAILED", "GhostSpiral",
  '                          + ", ".join(f"account {_a}/subaddr {_x}"\n'
  '                                      for _a, _x in _targets) + ".")',
  '                          + f"account {_vacct}/subaddr {_vidx}" + ".")',
  ["test_units"]),

 # The exit prints its recovery advice INSIDE the per-output loop, so two held
 # entry outputs read as two invitations to mint one wallet and send both --
 # a single transaction spending two publicly-settled swap chunks.
 ("two held ENTRY outputs may share one recovery bundle", "GhostSpiral",
  '        if _held_kinds["entry"] > 1:',
  "        if False:",
  ["test_exit_withdraw"]),

 # assign_hop_destinations guarantees "no destination twice" only WITHIN one
 # call, and build_dag_plan calls it once per chunk group plus once for
 # orphans. The orphan pass over the FULL mix_targets shared a destination in
 # 200 of 200 plans, every one of them merging two chunk groups.
 ("the orphan hop pass may re-take a destination another group has",
  "GhostSpiral",
  "            _free = [d for d in mix_targets if d not in set(_dsts.values())]",
  "            _free = list(mix_targets)",
  ["test_dag_entry"]),

 # ...and the cross-call check that also covers overlapping slices, which
 # build_dag_plan never verifies are a partition.
 ("two hops may share a destination across calls", "GhostSpiral",
  "            if _d in _by_dst:",
  "            if False:",
  ["test_dag_entry"]),

 # split_btc_amount works in integer satoshis, so a sub-satoshi total comes
 # back quantised while the docstring promises "The total is EXACT".
 ("a sub-satoshi total is quantised instead of refused", "GhostSpiral",
  "    if total != total.quantize(SATOSHI_BTC):",
  "    if False:",
  ["test_dag_entry"]),

 # create_fresh_account validates ONE answer and has no memory across calls,
 # so every loop that mints in bulk has to check for itself. create_subs,
 # create_entry_set and build_entry_veils do; these two did not.
 ("two change sweeps may pay the same fresh address", "GhostSpiral",
  "    if len(set(_cs_addrs)) != len(_cs_addrs) or len(set(_cs_accts)) != len(_cs_accts):",
  "    if False:",
  ["test_dag_entry"]),

 ("two peel hops may share a carrier or a change account", "GhostSpiral",
  "    if len(set(_pc_addrs)) != len(_pc_addrs) or len(set(hop_accounts)) != len(hop_accounts):",
  "    if False:",
  ["test_dag_entry"]),

 # The end-to-end split run must still notice a hop that silently goes missing.
 # Its old check ("hops every funded output") was FLAKY -- 9 failures in 25 --
 # because a chunk whose slice holds one subaddress has nowhere legal to hop,
 # so the assertion was stronger than the design. Loosening it to <= would have
 # hidden exactly this mutation; it counts the HOPPABLE outputs instead.
 ("the DAG round silently drops a hop it could have made", "GhostSpiral",
  "        _unassigned = [s for s in _fundable if s not in _dsts]",
  "        _dsts.pop(next(iter(_dsts)), None) if _dsts else None\n"
  "        _unassigned = [s for s in _fundable if s not in _dsts]",
  ["test_split_pipeline"]),

 # chain_safe strips the digits, so `delay:idx=7` becomes `delay:idx=#` -- and
 # a twelve-transaction round wrote TWELVE identical lines. Counting them gives
 # the batch size, which is what chain_safe's docstring says it prevents.
 ("a per-transaction line is chained again, so counting gives the batch size",
  "gs_common.py",
  "    if key in _CARDINAL_EVENTS_LOGGED:\n        return \"\"",
  "    if False:\n        return \"\"",
  ["test_units"]),

 # The positivity repair can put two chunks on the same satoshi just below the
 # feasibility floor -- [1, 1] for 2 satoshis across 2. Dropping the final
 # distinctness re-check lets that repeated deposit amount be RETURNED instead
 # of raised, which is the Bitcoin-side cluster the whole function removes.
 ("the split's distinctness re-check after the positivity repair is dropped",
  "GhostSpiral",
  "    if len(set(amounts)) != n:\n        raise ValueError(",
  "    if False:\n        raise ValueError(",
  ["test_dag_entry"]),

 # sorted() is stable, so keying the staircase on the satoshi value alone puts
 # TIED chunks in original index order and the lowest index always gets the
 # lowest amount. Measured P(a[i]<a[j]) = 0.66 at 36 satoshis across 8, where
 # 0.5 is unbiased -- the ordering tell the docstring says the write-back to
 # original indices removes.
 ("the chunk staircase breaks ties by index, so chunk order leaks chunk size",
  "GhostSpiral",
  "    _order = sorted(range(n), key=lambda i: (_sat[i], rng.random()))",
  "    _order = sorted(range(n), key=lambda i: _sat[i])",
  ["test_dag_entry"]),

 # THE SAME CARDINALITY LEAK ONE CALL DEEPER. verify_spend_source logs once per
 # CALL, and resolve_entry_accounts calls it once per entry -- so re-indexing it
 # puts one identical redacted line per --split chunk back on the chain.
 ("the per-entry spend-source proof is chained once per chunk again",
  "GhostSpiral",
  '    integrity_log_once("stage4", "spend_source_ok")',
  '    integrity_log("stage4", f"spend_source_ok:acct={account}:idx={index}")',
  ["test_units"]),

 # create_receive_wallet's mint_one_receive is called once per --count, so any
 # one of its success lines tallies to the number of receive addresses.
 ("the mint chains a line per --count turn again, giving the count away",
  "create_receive_wallet",
  '    integrity_log_once("wallet", "receive_account")',
  '    integrity_log("wallet", f"receive_account:{acct_idx}")',
  ["test_units"]),

 # resolve_destinations calls _dest_from_bundle in a LIST COMPREHENSION, which
 # the for/while sweep did not treat as a loop. One line per bundle, identical
 # after redaction, so counting them gives the swap batch size.
 ("the per-bundle destination line is chained once per bundle again",
  "thor_swap_preparer",
  '    integrity_log_once("thor", "dest_from_bundle")',
  '    integrity_log("thor", f"dest_from_bundle:{scrub_address(addr)}")',
  ["test_chain_redaction"]),

 # `quoted` has already been replaced by args.expect_total_xmr twenty lines up,
 # so dividing by it makes _scale exactly 1 and "RESCALE the breakdown" is a
 # no-op. The gate then compares the operator's total against the quotes' raw
 # per-chunk magnitudes, and below the quotes' sum it opens with a whole chunk
 # still in flight.
 ("the --expect-total-xmr breakdown rescale is a no-op (_scale is always 1)",
  "GhostSpiral",
  "            _scale = args.expect_total_xmr / _quoted_sum",
  "            _scale = args.expect_total_xmr / quoted",
  ["test_swap_arrival"]),

 # create_fresh_account has no memory across calls, and --count N calls it N
 # times. Seven other bulk loops in this toolchain check for a repeated answer;
 # this was the eighth and it merged the results without comparing them.
 ("--count accepts a wallet that hands back the same receive twice",
  "create_receive_wallet",
  '    if addr in seen_addrs:',
  '    if False:',
  ["test_swap_receive"]),

 ("--count accepts two receives landing in the SAME account (shared change sink)",
  "create_receive_wallet",
  '    if acct in seen_accts:',
  '    if False:',
  ["test_swap_receive"]),

 # The exit loop's Tor gates sit inside the try whose `except SystemExit` is
 # there for a failed ROUND. Without the re-raise, tor_recheck's
 # "[!] Tor leak detected" is swallowed, reported as an ordinary withdrawal
 # failure, and the loop re-runs the leaking gate on every remaining output.
 ("a mid-run Tor leak during the exit is swallowed as a withdrawal failure",
  "GhostSpiral",
  "            if not _gates_passed:\n                raise",
  "            if False:\n                raise",
  ["test_exit_withdraw"]),

 # _run_change_sweep calls _run_round, which sys.exits on a create/sign/
 # broadcast failure. Without the guard that abort leaves the sweep loop and
 # kills the pipeline BEFORE _run_exit_withdrawals runs, stranding every mixed
 # output -- while the loop's docstring promises "the remaining sweeps still
 # run".
 ("a failed change-sweep round kills the pipeline before the exit",
  "GhostSpiral",
  "        except SystemExit:\n            _outcomes.add(\"round_failed\")",
  "        except ZeroDivisionError:\n            _outcomes.add(\"round_failed\")",
  ["test_exit_withdraw"]),

 # redact_addresses matches 90+ base58 chars. Slicing to 160 characters BEFORE
 # redacting can cut a 95-char address below that floor, so it is not an
 # address to the regex and passes through verbatim -- measured at up to 89
 # characters of the wallet's primary address.
 ("the signer slices wallet-cli output BEFORE redacting it", "airgap_tx_signer",
  "{redact_addresses(_txt.strip())[-160:]}",
  "{redact_addresses(_txt.strip()[-160:])}",
  ["test_units"]),
]


def run(idx, name, fname, find, repl, suites):
    tmp = tempfile.mkdtemp(prefix=f"mutg5_{idx}_")
    dst = os.path.join(tmp, "repo")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", "integrity_chain.log*"))
    path = os.path.join(dst, fname)
    src = open(path).read()
    if src.count(find) != 1:
        print(f"[{idx:2d}] SKIP  {name}\n       anchor appears {src.count(find)}x")
        shutil.rmtree(tmp, ignore_errors=True)
        return "SKIP"
    open(path, "w").write(src.replace(find, repl, 1))
    # PROVE the mutation is on disk. A sweep that silently failed to apply
    # reports green and proves nothing.
    check = subprocess.run(["grep", "-qF", repl, path])
    if check.returncode != 0:
        print(f"[{idx:2d}] BROKEN {name}: replacement not found on disk")
        shutil.rmtree(tmp, ignore_errors=True)
        return "BROKEN"
    caught, verdicts = False, []
    for suite in suites:
        p = subprocess.run([sys.executable, f"tests/{suite}.py"], cwd=dst,
                           capture_output=True, text=True, timeout=900)
        out = p.stdout + p.stderr
        m = re.findall(r"(\d+) passed, (\d+) failed", out)
        if not m:
            verdicts.append(f"{suite}=NO-RESULT")
            continue
        failed = int(m[-1][1])
        verdicts.append(f"{suite}={'RED' if failed else 'green'}({failed})")
        if failed:
            caught = True
    shutil.rmtree(tmp, ignore_errors=True)
    tag = "CAUGHT" if caught else "*** SURVIVED ***"
    print(f"[{idx:2d}] {tag:16s} {name}\n       {'  '.join(verdicts)}")
    return "CAUGHT" if caught else "SURVIVED"


if __name__ == "__main__":
    only = set(sys.argv[1:])
    tally = {}
    for i, mut in enumerate(MUTATIONS):
        if only and str(i) not in only:
            continue
        r = run(i, *mut)
        tally[r] = tally.get(r, 0) + 1
    print("\n", tally)
