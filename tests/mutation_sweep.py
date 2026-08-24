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
  # Re-anchored twice: the held breakdown gained a third kind (a stopped peel
  # chain's undistributed remainder) and then a fourth (the operator's usage
  # fee), so the condition names four counts. Each addition has had to be made
  # here too, and the one that is not would announce a clean exit over value
  # the run deliberately kept back.
  "        elif _relayed and not (_held_entry or _held_change or _held_remainder\n"
  "                               or _held_fee):",
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
 #
 # TWO of them, with anchors that name which. This was ONE entry anchored on
 # "while _excess > 0:\n        _moved = False", which appears TWICE -- the BTC
 # split and the fan-out sizing grew the same give-back loop -- so the sweep
 # could not tell them apart and scored it SKIP on every run. A skipped
 # mutation is an untested guarantee wearing the same green as a caught one,
 # and it was skipped for both copies at once. The `for` line disambiguates
 # them: the BTC split iterates `n`, the fan-out `_n`.
 ("the distinctness give-back runs once instead of to convergence (BTC split)",
  "GhostSpiral",
  "    while _excess > 0:\n        _moved = False\n        for _pos in range(n - 1, -1, -1):",
  "    while _excess > 0 and False:\n        _moved = False\n        for _pos in range(n - 1, -1, -1):",
  ["test_dag_entry"]),

 ("the distinctness give-back runs once instead of to convergence (fan-out)",
  "GhostSpiral",
  "    while _excess > 0:\n        _moved = False\n        for _pos in range(_n - 1, -1, -1):",
  "    while _excess > 0 and False:\n        _moved = False\n        for _pos in range(_n - 1, -1, -1):",
  ["test_units", "test_dag_entry"]),

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

 # Re-anchored: the two-way ternary became _held_kind(), which has three
 # answers now (a peel chain's undistributed remainder is neither ENTRY nor a
 # distribution change).
 ("held outputs are all reported as ENTRY", "GhostSpiral",
  '        if pair in _entry_set:\n'
  '            return "entry"\n'
  '        if pair in _remainder_set:\n'
  '            return "remainder"\n'
  '        if pair in _fee_set:\n'
  '            return "usagefee"\n'
  '        return "change"',
  '        return "entry"',
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

 # Re-anchored: stage 2 execution moved out of main() into
 # resolve_swap_deposits, and ENTRY_ADDRS became the `entry_addrs` parameter.
 ("manual mode prints one --dests for every chunk", "GhostSpiral",
  '                  + " ".join(scrub_address(_a) for _a in entry_addrs)',
  '                  + scrub_address(entry_addrs[0])',
  ["test_dag_entry", "test_send_gates"]),

 # The exit hold is the LAST thing standing between a swap chunk that landed
 # late and a one-hop sweep to --exit-to from the address the OP_RETURN memo
 # names in public. Narrowing it to the funded subset is the obvious edit --
 # every other consumer wants the funded one -- and it fails silently: the run
 # reports success.
 ("the exit holds only the chunks that ARRIVED, not the full entry set",
  "GhostSpiral",
  # Re-anchored: the _stage5_run call grew dag_dst_index/sweep_targets, so
  # the line this ended on now ends in a comma rather than a bracket.
  "                                 exit_hold=_exit_hold_list(args, addr_index,\n"
  "                                                           ENTRY_ADDRS),",
  "                                 exit_hold=_exit_hold_list(args, addr_index,\n"
  "                                                           [_e[0] for _e in ENTRY_SET_FUNDED]),",
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
  # Re-anchored: the orphan pool gained the _safe_dsts filter.
  "            _free = [d for d in mix_targets\n"
  "                     if d in _safe_dsts and d not in set(_dsts.values())]",
  "            _free = [d for d in mix_targets if d in _safe_dsts]",
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
  # Re-anchored: the _gates_passed flag was replaced by RelayGateAbort, so the
  # thing that must not be swallowed is the re-raise in the exit's own loop.
  # (Mutation 61 covers the change-sweep loop, which has the same shape.)
  "            # A distinct exception type rather than the local flag this used to\n"
  "            # keep: the flag could not travel to the change-sweep loop, which\n"
  "            # has the same shape and the same catch. See RelayGateAbort.\n"
  "            raise",
  "            pass",
  ["test_exit_withdraw", "test_tor_gates"]),

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

 # paranoia_mode globs each root at depth 0 and 1 only. `r in res.parents` is
 # true at ANY depth, so a path two levels down answered "covered" and the
 # three "this will NOT be wiped" warnings stayed silent for it.
 ("wipe_covers claims coverage at any depth, not the depth 0/1 the sweep reaches",
  "gs_common.py",
  "        return any(res == r or res.parent == r\n                   for r in paranoia_search_roots())",
  "        return any(res == r or r in res.parents\n                   for r in paranoia_search_roots())",
  ["test_units"]),

 # Every fan-out share is quantised onto a 0.0001 XMR grid, so independent
 # draws collide: 81% of plans held a repeat at 0.5 XMR / --wallets 20. The
 # docstring's first line promises "DELIBERATELY UNEQUAL".
 # ---- the Pi/vault wake channel -----------------------------------------
 # The reflection: crypto_box gives ONE key both directions, so an M2 sealed to
 # the vault's STATIC key instead of its per-boot ephemeral makes the vault's
 # own M1, replayed, a valid answer that echoes the right challenge.
 ("the wake M2 is sealed to the static key, not the per-boot ephemeral",
  "gs_wake_agent",
  "    body = proto.open_record(eph, pi_pk, m2, proto.TAG_M2)",
  "    body = proto.open_record(tp_sk, pi_pk, m2, proto.TAG_M2)",
  ["test_wake_agent", "test_wake_endtoend"]),

 # The domain tag is the only thing separating M1 from M3, which DO share a key.
 ("the wake domain tag is not checked", "gs_wake_proto.py",
  "    if not hmac.compare_digest(inner[:TAG_LEN], expect_tag):",
  "    if False:",
  ["test_wake_protocol"]),

 # Unpadded, the job is readable off the wire by ciphertext length alone
 # (measured: 76 / 91 / 100 bytes for the three jobs).
 ("wake records are not padded, so the job leaks by length",
  "gs_wake_proto.py",
  "    padded = bindings.sodium_pad(inner, PAD_BLOCK)",
  "    padded = inner",
  ["test_wake_protocol"]),

 # The closed schema is the whole defence against flag injection from the
 # least-trusted box into the most-trusted one.
 ("the wake job schema accepts any key set", "gs_wake_proto.py",
  "    if got != want:",
  "    if False:",
  ["test_wake_protocol"]),

 ("the wake job whitelist accepts any job id", "gs_wake_proto.py",
  "    if not isinstance(job, str) or job not in JOBS:",
  "    if False:",
  ["test_wake_protocol"]),

 # THE ONE THAT MATTERS MOST: without this the vault stays powered on, on the
 # LAN, with the disk auto-unlocked, on every refusal path there is.
 ("the vault does not power off when a wake refuses", "gs_wake_agent",
  '        if code not in ("inhibited", "mix_running"):\n'
  "            power_off(dry_run=args.dry_run)",
  "        pass",
  ["test_wake_agent"]),

 # Every refusal PAST COLLECTION owes the doorbell an answer. Without this the
 # Pi times out and tells the operator "this job may already be done. CHECK THE
 # VAULT" when nothing ran.
 ("a post-collection refusal never reaches the doorbell", "gs_wake_agent",
  "    except (Refused, SystemExit) as e:\n"
  '        report_back(key, job_id, challenge.hex(), "refused", "",\n'
  '                    poster=d.get("post_record"))\n'
  "        raise e",
  "    except (Refused, SystemExit) as e:\n        raise e",
  ["test_wake_agent"]),

 # A slow answer was structurally unreportable while the window was checked
 # before the job_id had been read out of the note.
 ("a slow answer is refused without telling the doorbell", "gs_wake_agent",
  "        raise _reported(key, d, job_id, challenge, Refused(\n"
  '            "slow_answer",',
  "        raise (lambda k, dd, j, c, e: e)(key, d, job_id, challenge, "
  "Refused(\n"
  '            "slow_answer",',
  ["test_wake_agent"]),

 # 65536 handles: at ~300 recorded, a repeat is more likely than not, and this
 # dict is keyed on the handle -- a repeat overwrites the record it lands on
 # and a later watch follows the newer job's address.
 ("a colliding handle overwrites the record it lands on", "gs_wake_agent",
  "    for _ in range(64):\n"
  "        if handle not in handles:\n"
  "            break\n"
  "        handle = proto.new_handle()",
  "    for _ in range(0):\n"
  "        if handle not in handles:\n"
  "            break\n"
  "        handle = proto.new_handle()",
  ["test_wake_agent"]),

 # The integrity chain redacts addresses; a MAC had no rule at all and bech32
 # fell through to the digit rule, which left most of the address in order.
 ("the chain redactor passes MAC addresses through", "gs_common.py",
  '        out = _CHAIN_MAC_RE.sub("<mac>", out)',
  "        pass",
  ["test_chain_redaction"]),
 ("the chain redactor passes bech32 BTC addresses through", "gs_common.py",
  '        out = _CHAIN_BECH32_RE.sub("<addr>", out)',
  "        pass",
  ["test_chain_redaction"]),

 # The dedupe marker is a second copy of every chain payload, keyed on the RAW
 # value and written to disk beside the plans.
 ("the dedupe marker stores the unredacted payload", "gs_common.py",
  '        _line = f"{chain_safe(stage)}\\t{chain_safe(kind)}\\n"',
  '        _line = f"{stage}\\t{kind}\\n"',
  ["test_chain_redaction"]),

 # A path whose last component contains a dot was treated as a FILE and
 # replaced by its parent, so a directory two levels down reported "covered".
 ("wipe_covers calls a dotted directory covered", "gs_common.py",
  "        if res.is_file():\n"
  "            res = res.parent\n"
  "        elif not res.exists() and res.suffix:\n"
  "            res = res.parent",
  "        if res.is_file() or res.suffix:\n            res = res.parent",
  ["test_units"]),

 # compare_digest raises TypeError on non-ASCII str, and this one comes off the
 # wire -- so any local process could kill a handler thread before auth.
 ("a non-ASCII token crashes the console's request thread", "gs_console",
  "        try:\n"
  '            got = t.encode("utf-8", "surrogatepass")\n'
  '            want = TOKEN.encode("utf-8", "surrogatepass")\n'
  "        except (UnicodeError, AttributeError):\n"
  "            return False\n"
  "        return hmac.compare_digest(got, want)",
  "        return hmac.compare_digest(t, TOKEN)",
  ["test_console"]),

 # --job-timeout was inert for every job the page can start.
 ("--job-timeout does nothing for a job started from the page", "gs_console",
  # RE-ANCHORED: the branch gained the "shorter than the estimate" warning
  # between the `if` and the `return`, so the old two-line find matched
  # nothing and this guarantee was going UNSWEPT. Anchored on the `if` alone.
  # ...on the RETURN, not the `if`: `if JOB_TIMEOUT_EXPLICIT:` appears twice
  # in this file (here and in main), and an anchor matching twice does not
  # apply either. Falling through to the estimate IS the original defect.
  "        return JOB_TIMEOUT_S",
  "        pass",
  ["test_console"]),

 # The exit plan names the operator's FINAL destination and was written to the
 # shell's cwd rather than the 0700 --output directory.
 ("the exit plan is written to the working directory", "GhostSpiral",
  '        path = _outdir / f"unsigned_exit_{secure_hex(6)}.json"',
  '        path = Path(staging_dir).parent / f"unsigned_exit_{secure_hex(6)}.json"',
  ["test_exit_withdraw"]),

 # The header promises the daemon egress check runs before EVERY submit; with
 # no --rpc-daemon it runs on none of them.
 ("the egress gate is silent about not running", "broadcast_signed_xmr",
  "            if not EgressGate._warned_no_daemon:",
  "            if False:",
  ["test_broadcast"]),

 # THE WORST LEAK THIS FEATURE HAS HAD. A systemd unit with no StandardOutput=
 # journals everything its children print, and the children print the ThorChain
 # memo -- which names the destination XMR address in plain text -- into
 # /var/log/journal, outside everything paranoia_mode sweeps.
 ("the woken job's output goes to the systemd journal",
  "systemd/gs-wake-agent.service",
  "StandardOutput=null\nStandardError=null\n",
  "",
  ["test_wake_agent"]),

 # The other half: the child must not inherit this process's stdout either.
 ("a woken job's child inherits the agent's stdout", "gs_wake_agent",
  "                             stdout=sink or subprocess.DEVNULL,\n"
  "                             stderr=subprocess.STDOUT,\n",
  "",
  ["test_wake_agent"]),

 # flock conflicts are per open file description, not per process, so a handler
 # that takes the chain lock blocks on a lock only the code it interrupted can
 # release. The process then cannot be interrupted at all, the operator reaches
 # for kill -9, and SIGKILL runs no finally -- leaving .gs_pw_* on disk.
 ("a signal handler takes the integrity-chain lock and deadlocks",
  "gs_common.py",
  '    _PENDING_CHAIN.append(("signal", f"shutdown_requested_sig={signum}"))',
  '    integrity_log("signal", f"shutdown_requested_sig={signum}")',
  ["test_concurrency"]),

 # The arrival gate decides the money has landed. With chunks=1 the floor is
 # just the slippage tolerance, so a whole swap can be missing.
 ("the swap arrival gate forgets how many swaps there are", "receive_watch",
  "        len(_chunk_amounts) or len(matched) or 1)",
  "        len(_chunk_amounts) or 1)",
  ["test_receive_watch"]),

 # monero-python dumps whole JSON-RPC responses to stderr on any error, past
 # every redactor in this repository, because logging.lastResort is a stderr
 # handler and "no handler configured" is not "no output".
 ("a dependency's logger writes unredacted RPC responses to stderr",
  "gs_common.py",
  "\n\n_silence_third_party_logging()\n",
  "\n\npass  # mutated\n",
  ["test_env_leaks"]),

 # Under `sudo paranoia_mode` -- which the tool's own failure text recommends --
 # os.getuid() is root, and the "uid-scoped" sweep becomes a blanket sweep of
 # every root-owned entry in /tmp: systemd-private-*, .X11-unix, running units.
 ("the temp sweep deletes root's /tmp when run under sudo", "paranoia_mode",
  '        if uid == 0 and os.environ.get("SUDO_UID"):\n'
  '            uid = int(os.environ["SUDO_UID"])',
  "        pass",
  ["test_shmwipe"]),

 # HISTFILE is a shell VARIABLE, never exported, so the environment lookup was
 # dead in exactly the case its own docstring names -- and that file can hold a
 # --wallet-password verbatim.
 ("a relocated shell history is missed by the wipe", "paranoia_mode",
  # A SYNTAX-BREAKING mutation would score NO-RESULT, which proves nothing --
  # so this kills the feature while leaving the file valid: the pattern simply
  # never matches an assignment anybody writes.
  '        for hit in re.finditer(r"^\\s*(?:export\\s+)?HISTFILE=(\\S+)\\s*$",',
  '        for hit in re.finditer(r"^\\s*(?:export\\s+)?NEVERMATCHES=(\\S+)\\s*$",',
  ["test_shmwipe"]),

 # Everything below the summary's completion line used to sit under
 # `elif not bad:`, so a run with one failed phase printed none of it -- and a
 # non-root run always fails the MAC spoof.
 ("the wallet caveat is unreachable on a run that had failures",
  "paranoia_mode",
  "    if not args.dry_run:\n"
  "        # THE BIGGEST THING THIS TOOL DOES NOT DO, said out loud.",
  "    if not args.dry_run and not bad:\n"
  "        # THE BIGGEST THING THIS TOOL DOES NOT DO, said out loud.",
  ["test_gapfixes"]),

 # #recv-fields is hidden in send mode, not removed, so the browser kept the
 # last receive value and it became the swap arrival gate for a send run.
 ("a send run reads its arrival target from a hidden input", "gs_console",
  "  expect_total_xmr: mode==='receive' ? v('expect_total_xmr')\n"
  "                                     : v('expect_total_xmr_send'),",
  "  expect_total_xmr:v('expect_total_xmr'),",
  ["test_console"]),

 # THE ONE THING THE SHORT PAIRING CODE DEPENDS ON. Without the commitment
 # check the initiator picks its key after seeing the responder's, so a man in
 # the middle grinds keypairs until the two codes agree -- about 2^20 X25519
 # keygens for 40 bits, i.e. seconds -- and the operator compares two identical
 # strings while somebody sits between them.
 ("the pairing commitment is not checked, so the code can be ground to match",
  "gs_wake_proto.py",
  "    if not hmac.compare_digest(pair_commitment(peer_pub), commitment):",
  "    if False:",
  ["test_wake_protocol"]),

 # The SD card is the one that leaves the building in a pocket, and 0400 means
 # nothing to somebody reading it on their own machine.
 ("the Pi accepts an UNSEALED keyfile", "gs_doorbell",
  "    if not proto.keyfile_is_sealed(container):",
  "    if False:",
  ["test_wake_doorbell"]),

 # Both numbers come off a disk an attacker may have written to, and memlimit
 # is an allocation: a keyfile can otherwise OOM the box that reads it.
 ("Argon2 parameters off the disk are used unchecked", "gs_wake_proto.py",
  "    if (isinstance(mem, bool) or not isinstance(mem, int)\n"
  "            or not 2**23 <= mem <= 2**30):",
  "    if False:",
  ["test_wake_protocol"]),

 # A port scanner, a monitoring probe or a half-open connection must not
 # consume the ceremony and leave the real Pi with 'connection refused'.
 ("one stray connection consumes the pairing ceremony", "gs_wake_keys",
  "            except (proto.WakeError, OSError) as e:",
  "            except (proto.PairAborted,) as e:",
  ["test_wake_endtoend"]),

 # A regex that counts digits is not a check that the number is a byte. The
 # value goes into the Pi's keyfile and then into sendto().
 ("999.1.1.1 is accepted as a broadcast address", "gs_wake_keys",
  # RE-ANCHORED: the return gained the leading-zero guard str(int(p)) == p,
  # so the old exact find matched nothing and this went UNSWEPT too.
  '    return all(str(int(p)) == p and 0 <= int(p) <= 255 for p in v.split("."))',
  "    return True",
  ["test_wake_endtoend"]),

 # A built-in SD reader with no card publishes removable=1 forever, so without
 # the size check the vault refuses EVERY boot: a feature that never runs.
 ("an empty card slot counts as attached media", "gs_wake_agent",
  '        try:\n'
  '            if (Path(p).parent / "size").read_text().strip() == "0":\n'
  "                continue\n"
  "        except OSError:\n"
  "            pass\n",
  "",
  ["test_wake_agent"]),

 # paranoia_mode sweeps cwd/$HOME; systemd starts a unit with cwd=/ and
 # HOME=/root. Without this line the wake artifacts sit where the wipe never
 # looks -- and the agent, correctly, refuses to run at all.
 ("the wake artifacts land outside every wipe root",
  "systemd/gs-wake-agent.service",
  "WorkingDirectory=/var/lib/ghostspiral\nEnvironment=HOME=/var/lib/ghostspiral",
  "WorkingDirectory=/\nEnvironment=HOME=/root",
  ["test_wake_agent"]),

 # A pairing that half-succeeded reads as a pairing that must be re-keyed on
 # both boxes, when in fact nothing was ever paired.
 ("a relative artifact dir is written into the keyfile", "gs_wake_keys",
  "    if not os.path.isabs(args.artifact_dir):",
  "    if False:",
  ["test_wake_endtoend"]),

 # The dwell shipped as two dead constants and a doc claim for a whole draft.
 # An anchor here is the standing guard against it going dead again.
 ("a no-job boot powers off the instant it is told there is no job",
  "gs_wake_agent",
  "        _sleep(_rng.randint(NO_JOB_DWELL_LO_S, NO_JOB_DWELL_HI_S))",
  "        pass",
  ["test_wake_agent"]),

 # A Tor-down boot must refuse BEFORE asking, or it silently burns the poke.
 ("a Tor-down boot consumes the job anyway", "gs_wake_agent",
  '    if not _tor(key.get("tor_proxy", "")):',
  "    if False:",
  ["test_wake_agent"]),

 # A watch is a watch against a QUOTE. Without this the literal string "None"
 # reached receive_watch's --pairs, and the only alternative -- --any -- would
 # page the operator that their money landed when what landed was dust.
 ("a handle with no swap quote is watched anyway", "gs_wake_agent",
  '        if not slip:\n'
  '            raise Refused(\n'
  '                "no_quote",',
  "        if False:\n"
  "            raise Refused(\n"
  '                "no_quote",',
  ["test_wake_agent"]),

 # One handle, one address. --count 4 writes four bundles and new[0] is
 # whichever sorts first.
 ("a multi-bundle handle resolves to an arbitrary one of them",
  "gs_wake_agent",
  '            handles[handle] = {"bundle": new[0] if len(new) == 1 else None,\n'
  '                               "minted": len(new), "slip": None}',
  '            handles[handle] = {"bundle": new[0], "slip": None}',
  ["test_wake_agent"]),

 # "did not authenticate" and "authenticated, then refused" are different facts
 # about who is on the other end. Collapsed, a duplicate result from the vault
 # reads as a stranger posting noise on the switch.
 ("a refused result is reported as one that did not authenticate",
  "gs_doorbell",
  "                except Doorbell:\n"
  "                    # AUTHENTICATED AND THEN REFUSED",
  "                except Doorbell:\n"
  '                    pending.events.append("result_bad")\n'
  "                    return self._reply(204)\n"
  "                except Doorbell:\n"
  "                    # AUTHENTICATED AND THEN REFUSED",
  ["test_wake_doorbell"]),

 # The event that means "your job did not go where you think" was collected
 # and read by nothing.
 ("a second authenticated boot takes the job silently", "gs_doorbell",
  "def report(pending: Pending) -> int:\n    _report_events(pending)",
  "def report(pending: Pending) -> int:",
  ["test_wake_doorbell"]),

 # The ledger is what stops a re-issued job_id running twice and overwriting a
 # slip the operator may already have sent BTC against.
 ("the wake ledger does not stop a replayed job_id", "gs_wake_agent",
  '    if job_id in {j.get("id") for j in state["jobs"]}:',
  "    if False:",
  ["test_wake_agent"]),

 # One job, once: the doorbell caches its answer against (eph_pk, challenge) so
 # a retry and a LAN replay are the same request.
 ("the doorbell hands the job over on every fetch", "gs_doorbell",
  "        cached = self._issued.get((eph, chal))\n"
  "        if cached is not None:\n"
  '            self.events.append("m1_retry")\n'
  "            return cached",
  "        pass",
  ["test_wake_doorbell"]),

 # The doorbell may learn a 4-hex label and nothing else.
 ("the doorbell accepts any handle length", "gs_doorbell",
  '        if status == "done":\n'
  "            if not proto.HANDLE_RE.match(handle):",
  "        if False:\n"
  "            if not proto.HANDLE_RE.match(handle):",
  ["test_wake_doorbell"]),

 # time.monotonic() is seconds since BOOT on Linux, so a rate-limiter starting
 # at 0.0 asks "is this host older than ten minutes?" instead of "have I
 # reported yet?" -- and suppresses the FIRST "an entry address could not be
 # read" line on a freshly booted machine. The total is 7 of 10 XMR either way;
 # that line is the only thing saying the missing 3 was unreadable rather than
 # absent, and it feeds the arrival gate.
 ("the first unreadable-entry warning is lost near boot", "GhostSpiral",
  '    state = {"beat": None, "clock": clock or time.monotonic}',
  '    state = {"beat": 0.0, "clock": clock or time.monotonic}',
  ["test_swap_arrival"]),

 # ...and removing the limit outright fixes that case by re-creating the flood
 # it exists to prevent: one line per 30s poll across a multi-hour wait.
 ("the unreadable-entry warning is not rate-limited at all", "GhostSpiral",
  '        if (blind or stale) and (state["beat"] is None\n'
  '                                 or now - state["beat"] >= UNREADABLE_REPORT_S):',
  "        if blind or stale:",
  ["test_swap_arrival"]),

 # A peeling chain that stops part-way leaves EVERYTHING it had left on one
 # carrier -- each peel consumes its carrier exactly and pays the rest forward.
 # Driven through the shipped main(), the exit swept 9.62 of 12 XMR from that
 # carrier to --exit-to, unmixed, and printed "EXIT COMPLETE".
 ("a stopped peel chain's undistributed remainder is withdrawn to --exit-to",
  "GhostSpiral",
  "        if _stuck_carrier:\n"
  "            _hold.append((int(_stuck_carrier[0]), int(_stuck_carrier[1])))",
  "        if False:\n"
  "            _hold.append((int(_stuck_carrier[0]), int(_stuck_carrier[1])))",
  ["test_peel_pipeline", "test_exit_withdraw"]),

 # ...and the pair it holds has to be the carrier the chain STOPPED on. Naming
 # the peel that DID run holds an address that is already empty and leaves the
 # remainder to the exit, which is the same defect wearing a hold.
 ("the peel remainder hold names the wrong carrier", "GhostSpiral",
  "            _stuck_carrier = peel_stuck_carrier(_peel_txs, _relayed,\n"
  "                                                tuple(change_target))",
  "            _stuck_carrier = peel_stuck_carrier(_peel_txs, _relayed - 1,\n"
  "                                                tuple(change_target))",
  ["test_peel_pipeline"]),

 ("the fan-out amounts may repeat (the equal-value cluster)", "GhostSpiral",
  # Re-anchored, and closer to the defect it names: the staircase now RETURNS
  # directly and the give-back failure refuses with []. The old behaviour --
  # "a repeat is a weaker failure than an over-budget plan" -- was to hand back
  # the original draw, repeats and all, which is what this restores.
  '    integrity_log("stage4", "fanout_refused:indistinct_amounts")\n'
  "    return []",
  '    integrity_log("stage4", "fanout_refused:indistinct_amounts")\n'
  "    return amounts",
  ["test_units"]),

 # ---- the audit of 9da2e24's own regressions ----------------------------
 # Popped is not written: the drain emptied _PENDING_CHAIN before the write
 # loop, so ONE failed write lost every queued signal line.
 ("a failed chain write drops the deferred lines", "gs_common.py",
  "            if _written < len(pending):\n"
  "                _PENDING_CHAIN[:0] = pending[_written:]",
  "            pass",
  ["test_concurrency"]),

 # `$` also matches before a trailing newline, and int("4\n") == 4, so the
 # range guard did not catch it either. The value composes a URL.
 ("a MAC with a trailing newline reaches the keyfile", "gs_wake_keys",
  # RE-AIMED AT MAC_RE, and the reason is worth writing down.
  #
  # Anchored on IPV4_RE this SURVIVED twice, and the second time the harness
  # was right: is_ipv4's octet guard `str(int(p)) == p` ALSO rejects "4\\n",
  # so flipping that regex back to `$` changes is_ipv4's answer on nothing.
  # IPV4_RE is used at exactly one call site -- is_ipv4 itself -- so the \\Z
  # there is genuine defence in depth with a second layer behind it, and a
  # single-mutation sweep cannot observe it. Pinning it needs a direct
  # assertion on the regex, which test_wake_endtoend now also makes.
  #
  # MAC_RE is the one that is load-bearing: gs_wake_keys:166 and :304 use it
  # directly, with no octet-style guard behind it, so its \\Z is the ONLY
  # thing standing between "de:ad:be:ef:ca:fe\\n" and a keyfile.
  'MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\Z")',
  'MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")',
  ["test_wake_endtoend"]),

 # Same hole on the LAN-facing path, which is the one that matters: this value
 # comes off the wire and goes straight into a keyfile.
 ("_pair_info accepts a trailing newline off the wire", "gs_wake_proto.py",
  '                    r"^(\\d{1,3}\\.){3}\\d{1,3}\\Z", v) or any(',
  '                    r"^(\\d{1,3}\\.){3}\\d{1,3}$", v) or any(',
  ["test_wake_protocol"]),

 # An incompatible wire change with no version bump lets two boxes agree to
 # pair and then fail at wake time.
 ("PAIR_PROTO is not bumped for the wire break", "gs_wake_proto.py",
  "PAIR_PROTO = 4",
  "PAIR_PROTO = 2",
  ["test_wake_protocol"]),

 # Half a pairing: only the receiver validated, so the box holding a bad value
 # wrote its keyfile while the peer wrote none.
 ("_pair_config does not validate the info it sends", "gs_wake_proto.py",
  '        _pair_info({"info": my_info})',
  "        pass",
  ["test_wake_protocol"]),

 # chain_safe strips every digit, and on a terminal line the digits ARE the
 # diagnosis -- the RPC error code, the port that says which endpoint refused.
 ("the signer's failure line loses the RPC error code", "airgap_tx_signer",
  "terminal_safe(str(e))[:160]",
  "chain_safe(str(e))[:160]",
  ["test_chain_redaction"]),

 # scrub_address fragments of bech32 escaped: base58 excludes 0 and l, which
 # bech32's alphabet contains. 39.6% of bc1q fragments leaked in order.
 ("the scrub fragment rule misses bech32 again", "gs_common.py",
  '    r"[0-9A-Za-z]{4,}\\.\\.\\.[0-9A-Za-z]{4,}")',
  '    r"[1-9A-HJ-NP-Za-km-z]{4,}\\.\\.\\.[1-9A-HJ-NP-Za-km-z]{4,}")',
  ["test_chain_redaction"]),

 # A dry run that errored printed a SUCCESS line and exited 1 with no reason.
 ("a failed dry run goes back to exiting 1 in silence", "paranoia_mode",
  # ANCHORED ON THE GUARD, not on the first line of a multi-line print: that
  # mutation left the remaining lines printing and the sweep SURVIVED, which
  # is the harness telling the truth about a bad mutation rather than about
  # the code. `if False:` removes the whole report.
  "        if bad:",
  "        if False:",
  ["test_gapfixes"]),

 # Typing the flag's own advertised default cut a 361-day job to 8 days, and
 # the only warning fired BELOW the floor -- which that number IS.
 ("the job-timeout override stops saying it is the shorter number",
  "gs_console",
  "        if JOB_TIMEOUT_S < _estimate:",
  "        if False:",
  ["test_console"]),

 # StandardOutput=null took the agent's own refusal reasons with it, and
 # OnFailure powers the machine off. Nothing was left saying why.
 ("the wake agent's refusal reason stops reaching durable storage",
  "gs_wake_agent",
  "        _fd = os.open(str(_p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
  '        with os.fdopen(_fd, "a") as _fh:\n'
  '            _fh.write(msg.rstrip("\\n") + "\\n")',
  "        pass",
  ["test_wake_agent"]),

 # send_error bypassed the banner suppression, so the Pi's wall clock was one
 # malformed request away.
 ("the doorbell leaks its clock on the error path again", "gs_doorbell",
  "    def send_error(self, code, message=None, explain=None):",
  "    def _unused_send_error(self, code, message=None, explain=None):",
  ["test_wake_doorbell"]),

 # An M1 with no window field is an old build, not an intruder -- and the
 # agent told the operator it looked like a stranger's magic packet.
 ("an old build's M1 goes back to looking like an intruder", "gs_doorbell",
  '            self.events.append("m1_no_window_field")',
  "            pass",
  ["test_wake_doorbell"]),

 # THE PI DID NOT ACTUALLY WORK, and these two are why.
 #
 # The fetch window was spent while the vault was still switched off: the Pi
 # sends the magic packet and then, if its own pre-WOL delay ran past the
 # window, immediately tears the listener down. Driven at HEAD~: delay 700 s
 # -> ConnectionRefusedError, outcome=expired_uncollected. 33.2% of pokes, or
 # 46.7% once real boot time is allowed for.
 ("the fetch window is burned before the magic packet is sent", "gs_doorbell",
  "        pending.arm()\n",
  "",
  ["test_wake_doorbell"]),

 # The result window ignored the vault's 300-1200 s jitter AND the fact that
 # budget_s is spent PER STEP, so every job could report into a closed socket
 # and be recorded as collected_no_result after running fine.
 ("the result window forgets the vault's jitter and its per-step budget",
  "gs_doorbell",
  "        return (self.clock() - self.collected_at) < self.result_budget_s",
  "        return (self.clock() - self.collected_at) < self.budget_s",
  ["test_wake_doorbell"]),

 # ProtectHome=yes hides a `pip install --user` dependency set, gs_common
 # imports requests at module scope, StandardError=null discards the
 # traceback, and OnFailure powers the machine off. The vault boots, dies and
 # shuts down with nothing anywhere saying why.
 ("a missing dependency goes back to being a silent poweroff",
  "systemd/gs-wake-agent.service",
  "ExecStartPre=",
  "#ExecStartPre=",
  ["test_wake_agent"]),

 # wipe_covers resolves against cwd and $HOME; the unit sets both and a shell
 # does not, so the "confirm the pairing works" command refused on the shipped
 # default and told a correct install it was broken.
 ("the wipe-root refusal stops naming the by-hand case", "gs_wake_agent",
  "                      f\"      paranoia_mode's sweep is anchored on cwd and \"\n"
  "                      f\"$HOME. If you are running this BY HAND to check a \"\n"
  "                      f\"pairing, run it the way the unit does:\\n\"\n",
  "",
  ["test_wake_agent"]),

 # ...and the pairing tool printed that same unusable command as the next step.
 ("the pairing tool goes back to printing a command that cannot run",
  "gs_wake_keys",
  "    if not wipe_covers(_ad):",
  "    if False:",
  ["test_wake_agent"]),

 # --phase create securely (UNRECOVERABLY) erases whatever --outdir names,
 # after the Tor and RPC checks succeed, with no confirmation anywhere. A typo
 # or a stale path destroyed the operator's own files.
 ("--outdir erases a directory this tool did not create", "airgap_tx_signer",
  "        _ours = _staging_strays(outdir)",
  "        _ours = []",
  ["test_signer_schema"]),

 # `$` also matches before a trailing newline. Thirteen shipped validators
 # anchored that way; 10 of 10 measured accepted "<good>\\n". The guard is
 # STRUCTURAL -- it walks the source -- so reverting any single one is caught.
 ("a validator goes back to anchoring with $ instead of \\Z", "gs_console",
  'PATH_RE = re.compile(r"^[A-Za-z0-9._/\\-]{1,200}\\Z")',
  'PATH_RE = re.compile(r"^[A-Za-z0-9._/\\-]{1,200}$")',
  ["test_units"]),

 # The egress gate ran once per TX, above the retry loop. Every attempt after
 # the first re-submitted on a sample taken before the first -- across a
 # newnym() and a 5-15 s delay, which is exactly when egress changes.
 ("only the first submit of a TX is egress-gated", "broadcast_signed_xmr",
  '                _egress_gate(f"broadcast_tx_{real_idx}_retry", force=False)',
  "                pass",
  ["test_broadcast"]),

 # "Will this be wiped?" needs the NAME as well as the location. Asking
 # wipe_covers said True for ~/gs/my_notes.json, which no pattern matches and
 # the sweep never touches -- and that file holds every deposit address and
 # every memo, so no warning was printed for the worst possible artifact.
 ("the slip warning goes back to asking the location only",
  "thor_swap_preparer",
  "    if not wipe_will_erase(_out):",
  "    if not wipe_covers(_out):",
  ["test_gitignore"]),

 # The memo was re-validated before the sender instructions were re-printed;
 # the DEPOSIT ADDRESS was not. A tampered address sends the BTC where
 # ThorChain never sees it, and the memo check cannot fire because the memo
 # can stay honest. Same file, same argument, applied to one field only.
 ("the BTC deposit address is handed over unchecked", "receive_watch",
  "    _baddr = [i for i, p in enumerate(matched)",
  "    _baddr = [] and [i for i, p in enumerate(matched)",
  ["test_receive_watch"]),

 # _memo_fields_bind reads fields 0..2, so a newline in field 3 rides through a
 # PERFECT bind and forges a second "To address:" line in the copy-paste block
 # every caller prints. Driven through the real thor CLI as a subprocess.
 #
 # THE ANCHOR IS THE SHARED CALL, not an inline rule, because the inline rule
 # is what went wrong. Three gates in this repo screen the same class of value
 # for the same reason; instruction_field_safe was widened to the C1 block
 # (U+0080-U+009F, where U+009B is the single-character CSI) and this one was
 # left behind, still C0-only. Reverting the call to a private copy is the
 # regression that actually happened, so it is the one mutated here.
 ("a memo that binds can still forge the sender instructions", "gs_common.py",
  "    if not instruction_field_safe(raw):\n"
  "        return False\n",
  "    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw):\n"
  "        return False\n",
  ["test_opsec_guarantees"]),

 # The manifest hash is unkeyed and sits beside the blob it covers, so it
 # cannot catch a tampered blob; wallet-cli decodes the blob and is the only
 # decoder available offline, and its confirmation is auto-answered "y".
 ("the signer stops cross-checking what wallet-cli says it signed",
  "airgap_tx_signer",
  "            _check_wallet_cli_agrees(\n"
  '                (result.stdout or "") + (result.stderr or ""),\n'
  "                _plan_destinations(plan, idx), idx)",
  "            pass",
  ["test_signer_schema"]),

 # ---- the Telegram pager: it may TRIGGER, it may never CARRY ------------
 # Any chat that reaches the wake channel can wake the vault. The allowlist is
 # the only thing between a stranger who found the bot and a poke.
 ("the pager answers any chat, not just the allowlisted one",
  "gs_telegram_pager",
  "        if not isinstance(cid, int) or cid not in self.allow:",
  "        if False:",
  ["test_telegram_pager"]),

 # OPSEC_SETUP.md section 8: "there is deliberately no job that takes an XMR
 # destination". Trailing arguments are how one would arrive.
 ("the pager accepts trailing arguments on a command", "gs_telegram_pager",
  "    if len(parts) > 2:\n        return \"\", {}, \"too many arguments\"\n",
  "",
  ["test_telegram_pager"]),

 # section 4: "If Tor is down, the bot does not start."
 ("the pager starts without proving Tor is up", "gs_telegram_pager",
  "    verify_tor(proxy)",
  "    pass",
  ["test_telegram_pager"]),

 # ---- fixes that shipped in 9da2e24 with NO anchor at all --------------
 # Reverting either of these left all 33 suites green, so nothing stopped a
 # later edit from quietly undoing them.
 #
 # An https:// wallet-RPC was spoken in CLEARTEXT with nothing saying so: the
 # scheme is not carried through to the connection.
 ("an https:// wallet-RPC is spoken in cleartext again", "gs_common.py",
  '        if (parsed.scheme or "http").lower() not in ("http", ""):',
  "        if False:",
  ["test_units"]),

 # The chain is UNKEYED, so anyone who can write the file can recompute every
 # hash below their edit. Claiming it detects a mid-file edit is false.
 ("verify_integrity_chain claims to catch an adversary who recomputes",
  "gs_common.py",
  "        THAT DID NOT RECOMPUTE",
  "        THAT EDITED IT",
  ["test_units"]),

 # Three of the four common MAC notations walked through the redactor, two of
 # them with no digits in them at all so the digit rule never fired either.
 ("the MAC rule goes back to covering only the colon form", "gs_common.py",
  '    r"(?<![0-9A-Za-z])(?:0[xX])?(?:"\n'
  '    r"(?:[0-9A-Fa-f]{2}[:-]){5,}[0-9A-Fa-f]{2}"\n'
  '    r"|(?:[0-9A-Fa-f]{4}\\.){2}[0-9A-Fa-f]{4}"\n'
  '    r"|[0-9A-Fa-f]{12}"\n'
  '    r")(?![0-9A-Za-z])")',
  '    r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z])")',
  ["test_chain_redaction"]),

 # ---- THE SEALED SLIP -------------------------------------------------
 # The slip is the one payload in this system that deliberately LEAVES the
 # vault, so every gate around it is load-bearing in a way the rest of the
 # wake channel's are not: what stops it is not that it stays put.

 # A slip and an M3 are sealed under the same static-static box in the
 # ThinkPad->Pi case. Only the domain tag separates them.
 ("open_slip stops checking the domain tag, so any record of the right size "
  "opens as a slip", "gs_wake_proto.py",
  "    if not hmac.compare_digest(inner[:TAG_LEN], TAG_SL):",
  "    if False:",
  ["test_sealed_slip"]),

 # The Pi has no key for a slip, so SHAPE is the only check it can make --
 # and it has to make it, or a mangled blob reaches a chat window where the
 # failure looks like the vault's fault.
 ("the doorbell relays a malformed slip instead of refusing it on the "
  "vault's own channel", "gs_doorbell",
  "        if slip and not proto.slip_is_wellformed(slip):",
  "        if False:",
  ["test_sealed_slip"]),

 # A refused or failed job quoted nothing. A slip attached to one is the
 # vault contradicting itself.
 ("the doorbell accepts a slip on a job that did not finish", "gs_doorbell",
  "        if slip and status != \"done\":",
  "        if False:",
  ["test_sealed_slip"]),

 # ...and the same rule on the side that WRITES it, because the doorbell's
 # copy is the second defence, not the first.
 ("the vault seals a slip for a job that failed or was refused",
  "gs_wake_agent",
  "        if status != \"done\":\n            return \"\"\n",
  "",
  ["test_sealed_slip"]),

 # One ladder slot goes in, so one quoted pair comes out. Picking one of
 # several deposit addresses to send money to is not a guess worth making.
 ("the vault seals whichever quoted pair happens to be first", "gs_wake_agent",
  "        if not isinstance(pairs, list) or len(pairs) != 1:\n"
  "            # ONE amount goes in (a single ladder slot), so one pair comes out.",
  "        if not isinstance(pairs, list) or not pairs:",
  ["test_sealed_slip"]),

 # The whole point of the feature: without this line the operator is told a
 # swap is ready and still handed no way to pay it.
 ("the pager never actually sends the slip it was given",
  "gs_telegram_pager",
  "            ok = self.send(chat_id, slip)\n"
  "            if not ok:",
  "            ok = True\n"
  "            if not ok:",
  ["test_sealed_slip"]),

 # gs_unseal is the LAST gate before real Bitcoin moves, on a different
 # machine from the one that built the quote.
 ("gs_unseal stops re-checking that the memo names its own destination",
  "gs_unseal",
  "    if not memo_binds_destination(memo, dest):",
  "    if False:",
  ["test_sealed_slip"]),

 ("gs_unseal prints a field that can forge a line in the block being copied",
  "gs_unseal",
  "    if bad:",
  "    if False:",
  ["test_sealed_slip"]),

 # The keyfile format and the wire are versioned separately -- the comment
 # said so for months while the code stamped WIRE_VERSION into every file.
 # Putting it back makes a wire bump silently unreadable every keyfile on
 # both boxes, which is repaired only by a re-pairing ceremony at a vault
 # that is deliberately far away.
 ("the keyfile is stamped with the WIRE version again, so a wire bump bricks "
  "every existing pairing", "gs_wake_proto.py",
  "    head = {\"schema\": KEYFILE_SCHEMA, \"version\": KEYFILE_VERSION, "
  "\"role\": role}",
  "    head = {\"schema\": KEYFILE_SCHEMA, \"version\": WIRE_VERSION, "
  "\"role\": role}",
  ["test_sealed_slip"]),

 # send() swallowing its failure was survivable while every reply was a status
 # line. It stopped being survivable when a reply started carrying the slip:
 # the operator sees a promise with nothing behind it, on a box they cannot
 # walk to, and the only record is a print() the unit routes to /dev/null.
 ("the pager treats a dropped reply as a delivered one again",
  "gs_telegram_pager",
  '            print(f"  [!] reply failed: {_redact(e)}")\n'
  "            return False",
  '            print(f"  [!] reply failed: {_redact(e)}")\n'
  "            return True",
  ["test_sealed_slip"]),

 # `if slip and not wellformed(slip)` reads as a complete gate and is not:
 # 0, [] and {} are falsy, so each skips validation and is stored.
 ("the doorbell's slip gate goes back to truthiness with no type check",
  "gs_doorbell",
  "        if not isinstance(slip, str):",
  "        if False:",
  ["test_sealed_slip"]),

 # terminal_safe redacts IDENTIFIERS and passes control characters through --
 # correct for its job, not enough for a Telegram username, which is a string
 # its owner chose and which --whoami prints to a terminal and a journal.
 ("a sender-chosen username goes back to reaching the terminal with its "
  "escape sequences intact", "gs_telegram_pager",
  '_CTRL_RE = re.compile(r"[\\x00-\\x1f\\x7f-\\x9f]")',
  '_CTRL_RE = re.compile(r"(?!x)x")',
  ["test_telegram_pager"]),

 # open_slip refuses floats (via parse_body). Without the same check on the
 # way out, the vault can seal a slip the delivery machine will not open --
 # and that lands at the machine holding the money, for a swap already quoted.
 ("seal_slip and open_slip stop refusing the same things", "gs_wake_proto.py",
  "    _refuse_floats(body)",
  "    pass",
  ["test_sealed_slip"]),

 # 568 characters decode to 424, 425 or 426 bytes depending on the "=" tail,
 # and only 424 is a slip. Without this the odd ones fail at the AEAD as "your
 # vault did not seal this", sending the operator after a compromise that did
 # not happen when a chat client mangled a character.
 ("a mangled paste goes back to reporting itself as a compromised vault",
  "gs_wake_proto.py",
  "    if len(box) != SLIP_PAD + BOX_OVERHEAD:",
  "    if False:",
  ["test_sealed_slip"]),

 # One lost POST over Tor is ordinary. Sending the operator to a vault they
 # cannot reach because of one is the outcome this whole feature exists to
 # avoid, and the blob is already in hand.
 ("a single lost POST goes back to costing the whole delivery",
  "gs_telegram_pager",
  "            if not ok:\n                time.sleep(SLIP_RETRY_S)\n"
  "                ok = self.send(chat_id, slip)\n",
  "",
  ["test_sealed_slip"]),

 # ---- THE PHONE-ONLY PATH ---------------------------------------------
 # Plaintext delivery exists because two designs failed on the same
 # assumption -- that the operator can reach a machine. Everything here is a
 # bound on what that costs.

 # THE DEFECT THE OPERATOR ACTUALLY HIT. receive_watch exits non-zero for
 # timeout, stalled and not_syncing alike; without this branch a probe that
 # finds nothing is a "failed job", and the phone is told the vault FAILED
 # while the money is simply still in flight.
 ("money still in flight goes back to being reported as a failed vault",
  "gs_wake_agent",
  # Re-anchored: the excuse covers both watching jobs now, because a watch
  # that ran its window and saw money confirming is not a failed job either.
  '        if rc != 0 and job in ("swap_status", "watch") and not hard:',
  "        if False:",
  ["test_plain_slip"]),

 # The switch is a keyfile field on the vault, so a stolen bot token cannot
 # ask for plaintext. Two answers to one question would put the payload in
 # the transcript AND in a blob.
 ("a vault can be configured for BOTH delivery modes at once",
  "gs_wake_agent",
  '    if ps and (k.get("delivery_public") or "").strip():',
  "    if False:",
  ["test_plain_slip"]),

 ("the doorbell relays a result carrying both payloads", "gs_doorbell",
  "        if slip and plain:",
  "        if False:",
  ["test_plain_slip"]),

 # The status word is rendered into a sentence the operator acts on. An
 # unknown word must be refused, not passed through as itself -- and the
 # closed set is also what stops the vault gaining a free-text channel into
 # a chat.
 ("the vault gains a free-text channel into a chat window", "gs_doorbell",
  "        if not proto.phase_is_known(phase):",
  "        if False:",
  ["test_plain_slip"]),

 # gs_wake_proto's header promises a version mismatch is caught before any
 # crypto and is "impossible to misread". Without an exact key set that was
 # true of a PAD_BLOCK change and false of a field addition.
 ("a half-upgraded pair goes back to silently dropping the payload",
  "gs_doorbell",
  "        if set(body) != _want:",
  "        if False:",
  ["test_wake_doorbell"]),

 # These strings are pasted into a message a human copies into a wallet. A
 # newline in the memo forges a line of it.
 ("the Pi relays deposit instructions it has not checked the shape of",
  "gs_doorbell",
  "        if plain and not proto.plain_slip_is_wellformed(plain):",
  "        if False:",
  ["test_plain_slip"]),

 ("the vault stops checking what the Pi will reject, so it powers off "
  "believing it delivered", "gs_wake_agent",
  "        if not proto.plain_slip_is_wellformed(body):",
  "        if False:",
  ["test_plain_slip"]),

 # An EXACT key set, not a superset: a field this Pi has never heard of must
 # not be forwarded to Telegram unexamined.
 ("a field the Pi has never heard of rides along into the chat",
  "gs_wake_proto.py",
  "    if not isinstance(obj, dict) or set(obj) != set(PLAIN_FIELDS):",
  "    if not isinstance(obj, dict):",
  ["test_plain_slip"]),

 # A probe reads whatever status file is on disk. Nothing else removes it, so
 # without this a probe whose child dies reports the PREVIOUS run's outcome --
 # an old "funded" becomes "landed and spendable" about money that never
 # arrived, and the operator stops watching for it.
 ("a probe goes back to reporting the previous probe's answer",
  "gs_wake_agent",
  # Re-anchored: `watch` writes the same status file now, so the clear has to
  # cover it or a 110-minute wait reports a three-minute probe's stale answer.
  '    if job in ("swap_status", "watch"):\n        try:\n'
  '            (artifact_dir / STATUS_FILE).unlink()\n',
  '    if False:\n        try:\n'
  '            (artifact_dir / STATUS_FILE).unlink()\n',
  ["test_plain_slip"]),

 # ---- THE /depo WIZARD -------------------------------------------------
 # Conversation state is the risky part of making a command interactive, not
 # the asking. Each of these is a bound on it.

 ("conversation state grows without limit on a 1 GB box",
  "gs_telegram_pager",
  "        if (chat_id not in self.convos) and len(self.convos) >= MAX_CONVOS:",
  "        if False:",
  ["test_depo_wizard"]),

 ("a half-finished /depo never expires, so the next stray message answers a "
  "question the operator has forgotten", "gs_telegram_pager",
  "        dead = [c for c, v in self.convos.items() "
  "if not v.alive(self.clock)]",
  "        dead = []",
  ["test_depo_wizard"]),

 # One attempt is what makes three choices mean three choices.
 ("the confirm gate can be guessed at until it is right",
  "gs_telegram_pager",
  # Re-anchored: the confirm step reads both wizards' fields now, but the
  # property is the same one -- the conversation is deleted BEFORE the answer
  # is checked, so a wrong answer cannot be retried against the same sum.
  # Re-anchored: the withdraw wizard no longer collects a handle, so the
  # confirm step reads one field. The property is unchanged -- the
  # conversation is deleted BEFORE the answer is checked, so a wrong answer
  # cannot be retried against the same sum.
  "        exit_to = c.exit_to\n"
  "        del self.convos[chat_id]\n",
  "        exit_to = c.exit_to\n",
  ["test_depo_wizard"]),

 # A real command typed mid-flow must not be swallowed as an answer.
 ("a command typed mid-conversation is eaten by the wizard",
  "gs_telegram_pager",
  '        if word.startswith("/"):',
  "        if False:",
  ["test_depo_wizard"]),

 ("the wizard accepts a slot outside the ladder", "gs_telegram_pager",
  "            if not word.isdecimal() or not 0 <= int(word) <= 7:",
  "            if not word.isdecimal():",
  ["test_depo_wizard"]),

 # REPRODUCED: "²".isdigit() is True and int("²") raises. Guarded by isdigit
 # the ValueError escaped step_convo -- no reply sent AND the conversation
 # left live, so the operator's next unrelated message was eaten as a slot
 # answer. isdecimal is the predicate that matches what int() accepts.
 ("a superscript digit goes back to escaping the slot check and leaving a "
  "conversation live and armed", "gs_telegram_pager",
  "            if not word.isdecimal() or not 0 <= int(word) <= 7:",
  "            if not word.isdigit() or not 0 <= int(word) <= 7:",
  ["test_depo_wizard"]),

 # REPRODUCED: /cancel@mybot -- the group form this file supports -- cancelled
 # the conversation via the "/" branch and then replied "nothing to cancel".
 # The one command whose job is to confirm nothing is armed said the opposite.
 ("/cancel goes back to reporting on a pop it did not perform",
  "gs_telegram_pager",
  "        had_convo = cid in self.convos",
  "        had_convo = False",
  ["test_depo_wizard"]),

 # The ladder bound checked only the top end, so a negative slot indexed from
 # the far end -- ladder[-1] is the largest rung. The only thing stopping it
 # was a range check in another file.
 ("a negative amount slot goes back to selecting the ladder's last rung",
  "gs_wake_agent",
  "        if not 0 <= slot < len(ladder):",
  "        if slot >= len(ladder):",
  ["test_depo_wizard", "test_wake_agent"]),

 # ---- FOUR DEFECTS THAT WERE LISTED AND THEN NOT FIXED -----------------
 # Each was reported to the operator, reproduced against the real code, and
 # then left alone across several commits. Anchored so that cannot repeat.

 # urllib follows 302 by default and this call carries no proxy, so a doorbell
 # answering a redirect made the vault POST its record to any host it named --
 # off the LAN entirely, outside the path section 4 exists to enforce.
 ("the vault goes back to following wherever the doorbell redirects it",
  "gs_wake_agent",
  "        with _no_redirect_opener().open(req, timeout=timeout) as r:",
  "        with urllib.request.urlopen(req, timeout=timeout) as r:",
  ["test_listed_bugs"]),

 # --dry-run sent a real M1, which TAKES the job -- the handover is
 # at-most-once -- and then ran create_receive_wallet and thor_swap_preparer
 # for real, while --help said "do everything except run a job".
 ("--dry-run goes back to spending a wake and running the real job",
  "gs_wake_agent",
  "    if args.dry_run:\n        agent_say(",
  "    if False:\n        agent_say(",
  ["test_listed_bugs"]),

 # The inhibit file means "a person is at this machine", and the moment they
 # reach for it is mid-job. Read only at preflight, the case it was written
 # for was the one case it could not see.
 ("somebody sitting down mid-job goes back to being invisible",
  "gs_wake_agent",
  "        if _inh.exists():",
  "        if False:",
  ["test_listed_bugs"]),

 # ThreadingHTTPServer starts a thread per connection; the socket timeout
 # bounds how LONG each lives, not how MANY, on a 1 GB Pi with Tor resident.
 ("the doorbell goes back to starting a thread per connection, unbounded",
  "gs_doorbell",
  "            over = self._live >= MAX_CONNECTIONS",
  "            over = False",
  ["test_listed_bugs"]),

 # A cap that never releases is worse than no cap: the doorbell would stop
 # answering after one flood and the vault would never collect a job again.
 ("the connection cap goes back to ratcheting shut instead of releasing",
  "gs_doorbell",
  "    def close_request(self, request):",
  "    def _unused_close_request(self, request):",
  ["test_listed_bugs"]),

 # ---- the last two off that same list ----------------------------------

 # A fan-out output is spent TWICE -- the DAG round sweeps it onward, the exit
 # sweeps that subaddress to the operator -- and min_hop_fundable reserves one
 # fee. This restores the floor that hopped and then could not pay to leave.
 ("the fan-out floor goes back to reserving the hop and not the exit sweep",
  "GhostSpiral",
  "    min_each = min_exit_fundable(fee_xmr, dag_enabled)\n"
  "    floor_total = min_each * Decimal(fanout_count)",
  "    min_each = (min_hop_fundable(fee_xmr) if dag_enabled\n"
  "                else (DUST_XMR * 2).quantize(DUST_XMR, rounding=ROUND_UP))\n"
  "    floor_total = min_each * Decimal(fanout_count)",
  ["test_listed_bugs"]),

 # The predicate itself, not just the caller: doubling the reserve is what
 # makes the floor cover the second sweep, so halving it back is the defect
 # with the call site left intact.
 ("the exit-fundability predicate goes back to counting one sweep",
  "GhostSpiral",
  "    after_hop = (compute_hop_amount(fanout_amt, fee_xmr) if dag_enabled\n"
  "                 else fanout_amt)\n"
  "    return compute_hop_amount(after_hop, fee_xmr) > DUST_XMR",
  "    return compute_hop_amount(fanout_amt, fee_xmr) > DUST_XMR",
  ["test_listed_bugs"]),

 # The DAG-OFF branch reserved nothing for the exit at all, and it is where
 # main() SENDS an operator whose fan-out was refused ("disable --dag-mixing").
 #
 # RE-ANCHORED. This first appended the old expression AFTER the closed form,
 # and SURVIVED -- because the next line was `amt = max(amt,
 # min_hop_fundable(fee_xmr))`, which put it straight back. The dag-off floor
 # and min_hop_fundable are the same inversion, equal at all 2000 fees
 # measured, so the max() was doing the whole job and the mutation changed
 # nothing. That max() is gone now (see min_exit_fundable: it never fired at
 # any fee, on either branch, which is what an equivalent mutant looks like),
 # so this anchor replaces the closed form outright and the defect is real.
 ("the DAG-off floor goes back to a bare dust margin the exit cannot sweep",
  "GhostSpiral",
  "    amt = (hop_fee_reserve(fee_xmr) * (2 if dag_enabled else 1)\n"
  "           + DUST_XMR * 2).quantize(DUST_XMR, rounding=ROUND_UP)",
  "    amt = (hop_fee_reserve(fee_xmr) * 2\n"
  "           + DUST_XMR * 2).quantize(DUST_XMR, rounding=ROUND_UP)\n"
  "    if not dag_enabled:\n"
  "        amt = (DUST_XMR * 2).quantize(DUST_XMR, rounding=ROUND_UP)",
  ["test_listed_bugs"]),

 # NO ANCHOR FOR "the exit floor may drop below the hop floor". There was one,
 # against `amt = max(amt, min_hop_fundable(fee_xmr))`, and it SURVIVED: the
 # closed form is at or above min_hop_fundable at every fee on both branches,
 # so the max() could not change an answer. The line is deleted rather than
 # anchored -- the same call compute_fanout_amounts' staircase guard got -- and
 # the relationship is checked directly in test_units, where it CAN fail.

 # --expect-xmr overrides the TOTAL. Discarding the breakdown with it drops
 # swap_arrival_floor back to assuming equal chunks, which is the assumption
 # its own docstring names as the one the JoinMarket path breaks.
 ("--expect-xmr goes back to discarding the per-chunk breakdown",
  "receive_watch",
  "            _chunk_amounts = [c * args.expect_xmr / _quoted_sum\n"
  "                              for c in _chunk_amounts]",
  "            _chunk_amounts = []",
  ["test_listed_bugs"]),

 # RE-ANCHORED. This first read "an incomplete breakdown is rescaled onto the
 # override anyway", against a completeness guard that refused to scale a
 # partial shape. The guard is gone: measured over 4000 random shapes the
 # partial rescale never opened a gate the count-only fallback would have held,
 # and refusing it was a SECOND answer to a question GhostSpiral's copy of this
 # gate already answers -- the drift sum_quoted_xmr's docstring exists to stop.
 #
 # What survived the guard is the honesty of the report: with a partial shape
 # the "smallest chunk" is inferred, not read, and the line used to claim
 # otherwise. That is what is anchored now.
 ("the gate goes back to calling an INFERRED smallest chunk a quoted one",
  "receive_watch",
  '        _basis = ("the smallest chunk this target implies is"\n'
  '                  if _shape_partial else "the smallest quoted chunk is")',
  '        _basis = "the smallest quoted chunk is"',
  ["test_listed_bugs"]),

 # The same distinction in GhostSpiral's copy of the gate, which had it for the
 # count-only case and not for the partial-shape one -- so it printed "The
 # smallest quoted chunk is" about a set that does not cover every swap in the
 # target. Measured: 1007 of 4000 random shapes with an unreadable quote.
 ("GhostSpiral's gate goes back to calling an inferred chunk a quoted one",
  "GhostSpiral",
  '        _basis = (f"Split equally, each of the {n_chunks} chunks would be"\n'
  "                  if not chunk_amounts\n"
  '                  else ("The smallest chunk this target implies is"\n'
  "                        if len(chunk_amounts) != n_chunks\n"
  '                        else "The smallest quoted chunk is"))',
  '        _basis = ("The smallest quoted chunk is" if chunk_amounts\n'
  '                  else f"Split equally, each of the {n_chunks} chunks would be")',
  ["test_listed_bugs"]),

 # "They contribute NOTHING to the target" and "the target below is built from
 # N pair(s) only" are true of the QUOTED sum and false of --expect-xmr, which
 # covers every swap. Printed unconditionally they told an operator the watch
 # would finish without the unreadable swaps -- the opposite of what it does.
 ("the unreadable-quote note goes back to describing a replaced target",
  "receive_watch",
  "            if args.expect_xmr is None:",
  "            if True:",
  ["test_listed_bugs"]),

 # It told an operator who passed --pairs that they had not. The count IS
 # known there; only the shape is missing, and those are different warnings.
 ("the gate goes back to saying 'without --pairs' on a run that passed them",
  "receive_watch",
  "    elif target > 0 and not _chunk_amounts and not matched:",
  "    elif target > 0 and not _chunk_amounts:",
  ["test_listed_bugs"]),

 # ---- found by auditing the least-anchored files -----------------------

 # The two long-lived servers never called install_signal_handlers, so the
 # core-dump suppression it carries never ran on the two processes that hold
 # the wallet spend password and the Pi's X25519 secret for their lifetimes.
 ("gs_doorbell goes back to dumping the Pi's secret into a core file",
  "gs_doorbell",
  "no_core_dumps()\n\nfrom pathlib import Path",
  "\nfrom pathlib import Path",
  ["test_listed_bugs"]),

 ("gs_console goes back to dumping the wallet password into a core file",
  "gs_console",
  "no_core_dumps()\n\n\nREPO = os.path.dirname(os.path.abspath(__file__))",
  "\n\nREPO = os.path.dirname(os.path.abspath(__file__))",
  ["test_listed_bugs"]),

 # secure_delete_file opened O_WRONLY on files this toolchain mints 0400 on
 # purpose -- the wake keypair and the delivery key, an X25519 secret each --
 # so for any non-root owner the wipe could not erase what it listed.
 ("the wipe goes back to being unable to erase a 0400 keyfile it owns",
  "gs_common.py",
  "    except PermissionError:",
  "    except PermissionError:\n        return False",
  ["test_listed_bugs"]),

 # ...and the retry must stay scoped to the caller's OWN file. Without the
 # ownership test it would widen, and then destroy, a 0400 file belonging to
 # somebody else that the caller could not otherwise touch.
 ("the 0400 retry goes back to widening a file the caller does NOT own",
  "gs_common.py",
  "            if (not stat_module.S_ISREG(rst.st_mode)\n"
  "                    or rst.st_uid != os.geteuid()):",
  "            if not stat_module.S_ISREG(rst.st_mode):",
  ["test_listed_bugs"]),

 # The only one of fifteen callers that threw the return value away, in the
 # command whose whole job is confirming the delivery secret left the vault.
 ("gs_delivery_key shred goes back to claiming success it never checked",
  "gs_delivery_key",
  "    if not secure_delete_file(path):",
  "    secure_delete_file(path)\n    if False:",
  ["test_listed_bugs"]),

 # gs_wake_status.json holds the arrived swap amount to the piconero and was
 # in NEITHER the wipe list nor .gitignore, while its three siblings in the
 # same artifact_dir were in both.
 ("the arrival amount goes back to surviving the wipe",
  "gs_common.py",
  '    "gs_wake_status.json",',
  '    "gs_wake_status_NOT_SWEPT.json",',
  ["test_gitignore"]),

 # The sweep matches location AND name; the warnings spoke only about
 # location. `--outfile myplan.json` in the cwd got "is outside every directory
 # paranoia_mode searches" -- false -- and a remedy that cannot fix a name.
 ("the wipe warning goes back to blaming the location whatever failed",
  "exit_strategy_simulator",
  '        _why = wipe_miss_reason(_out)\n        if _why == "name":',
  '        _why = "location"\n        if False:',
  ["test_listed_bugs"]),

 ("thor_swap_preparer's wipe warning goes back to blaming the location",
  "thor_swap_preparer",
  '        _why = wipe_miss_reason(_out)',
  '        _why = "location"',
  ["test_listed_bugs"]),

 # The classifier must agree with the predicate it explains: "" exactly when
 # the sweep would erase the file, or it explains a different question.
 ("wipe_miss_reason goes back to answering about the location alone",
  "gs_common.py",
  "    if loc and not named:\n"
  '        return "name"\n'
  "    if named and not loc:\n"
  '        return "location"\n'
  '    return "both"',
  '    return "location"',
  ["test_listed_bugs"]),

 # The sealed path (gs_unseal) and the plaintext path (the pager) gate the
 # SAME deposit address for the same human, and only one of them refused the
 # C1 block. U+009B is the single-character CSI, so a terminal honouring 8-bit
 # controls reads it as ESC [ -- which this gate blocks in its C0 form.
 ("the sealed path goes back to letting C1 controls through",
  "gs_common.py",
  "    return not any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f\n"
  "                   for ch in str(value))",
  "    return not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(value))",
  ["test_listed_bugs"]),

 # ...and it must not over-refuse either: 0xA0 up is printable text, and a
 # gate that ate those would reject legitimate values instead.
 ("the control gate goes back to eating printable text above 0x9f",
  "gs_common.py",
  "    return not any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f\n"
  "                   for ch in str(value))",
  "    return not any(ord(ch) < 0x20 or ord(ch) >= 0x7f for ch in str(value))",
  ["test_listed_bugs"]),

 # exit_strategy_simulator had NO anchor at all, which is how it kept two
 # defects its own comments had already written down.

 # "1e400" is named in the comment above the guard and is FINITE, so the
 # is_finite/positive pair passed it and quantize raised InvalidOperation --
 # a traceback out of main(), after Tor and the oracle round trip.
 ("the off-ramp amount goes back to a hand-rolled parse with no bound",
  "exit_strategy_simulator",
  "    args.amount = decimal_env(_src, _amt, positive=True,\n"
  "                              max_value=XMR_ABSURD_TOTAL)",
  "    args.amount = Decimal(str(_amt))\n"
  "    if not args.amount.is_finite() or args.amount <= 0:\n"
  '        sys.exit("[!] Amount must be a positive finite number")',
  ["test_listed_bugs"]),

 # The block that exists to name the ACTUAL failure only saw failures that
 # RAISE, so a 200 that parsed and carried no XMR market was reported as a Tor
 # problem -- with _bisq_err never bound.
 ("a Bisq reply with no XMR market goes back to being blamed on Tor",
  "exit_strategy_simulator",
  "            _bisq_err = ValueError(\n"
  '                f"Bisq answered and the response parsed, but it carried no "',
  "            _unused_bisq_err = ValueError(\n"
  '                f"Bisq answered and the response parsed, but it carried no "',
  ["test_listed_bugs"]),

 # ...and the remedy must follow the diagnosis. It said "did not fail on the
 # network" and then "Check Tor connectivity and retry" in the same message.
 ("the oracle remedy goes back to saying 'check Tor' after 'not the network'",
  "exit_strategy_simulator",
  '        + ("    Check Tor connectivity and retry." if _network and _cg_net else\n'
  '           "    Tor is not the problem; retry, or check whether the oracle\'s\\n"\n'
  '           "    response format has changed." if not _network and not _cg_net\n'
  "           else\n"
  '           "    CHECK BOTH: one oracle was unreachable and the other "\n'
  '           "answered.\\n"\n'
  '           "    Tor may be down for some destinations, and the oracle that "\n'
  '           "did answer\\n    sent something this tool cannot use.")',
  '        + "    Check Tor connectivity and retry."',
  ["test_listed_bugs"]),

 # A rate of 1e-9 passes `price > 0`, and main() returned NORMALLY printing
 # "Value: 0.00 USD / Prices from: bisq_oracle (live)" and wrote the plan.
 ("a live rate that values the holding at nothing is reported anyway",
  "exit_strategy_simulator",
  "    if fiat_rate <= 0 or fiat_val <= 0:",
  "    if False:",
  ["test_listed_bugs"]),

 # oracle_prices is coarsened so the timestamp cannot be inverted from a spot
 # rate; amount_out_fiat sat beside it at cent precision and handed the same
 # rate straight back.
 ("the fiat value goes back to inverting the coarsened oracle price",
  "exit_strategy_simulator",
  '        "amount_out_fiat": str((net * coarsen_rate(fiat_rate))\n'
  '                               .quantize(Decimal("0.01"))),',
  '        "amount_out_fiat": str(fiat_val),',
  ["test_listed_bugs"]),

 # `bool(existing)` cannot tell "the vault's delivery key" from "A delivery
 # key", and nothing read the key out of the file before asserting a match.
 ("the delivery refusal goes back to asserting a match it never checked",
  "gs_delivery_key",
  "        if _file_pub and vault_public and _file_pub != vault_public:",
  "        if False:",
  ["test_listed_bugs"]),

 # ...and the comparison is only possible because the PUBLIC key is recorded
 # in the head at mint time. Without it every file is the UNKNOWN case.
 ("the minted delivery key goes back to recording no public key",
  "gs_delivery_key",
  '    container["delivery_public"] = dpub',
  "    pass",
  ["test_listed_bugs"]),

 # The relay validated its per-TX delay strictly from the signed manifest and
 # COERCED it from the unsigned plan -- int() swallows bools, floats, numeric
 # strings and negatives, and the fallback had no cap at all.
 ("the relay goes back to coercing a delay out of an unsigned plan",
  "broadcast_signed_xmr",
  '                    if not delay_is_sane(tx["delay"]):\n'
  '                        _bad_delay = (pos, tx["delay"])\n'
  "                        by_idx = {}\n"
  "                        break\n"
  '                    by_idx[pos] = tx["delay"]',
  "                    try:\n"
  '                        by_idx[pos] = int(tx["delay"])\n'
  "                    except (TypeError, ValueError):\n"
  "                        by_idx = {}\n"
  "                        break",
  ["test_listed_bugs"]),

 # ...and the rule itself must keep both halves: the type/sign test AND the cap.
 ("the delay rule goes back to accepting a 31,700-year stall",
  "gs_common.py",
  "    return not cap or value <= MAX_PLANNED_DELAY",
  "    return True",
  ["test_listed_bugs"]),

 # ...and the THIRD reader must take the shared rule rather than coercing. It
 # does not mis-time a transaction; it sizes the kill timeout for the broadcast
 # child, so a coerced 10**12 makes that timeout ~31,700 years and the hang is
 # never killed.
 ("GhostSpiral goes back to coercing a plan delay into the kill timeout",
  "GhostSpiral",
  "                if not delay_is_sane(_d):\n"
  "                    raise ValueError(",
  "                if False:\n"
  "                    raise ValueError(",
  ["test_listed_bugs"]),
 # ------------------------------------------------------------------
 #  Round: the environment path, the coarsened rate, and the wipe's
 #  remaining blind spots.
 # ------------------------------------------------------------------

 # resolve_btc_amount ran with the other syntactic checks, three lines BEFORE
 # resolve_sensitive_inputs overwrote args.btc_amount from GS_BTC_AMOUNT. So
 # the sub-satoshi and split-minimum refusals were applied to the argv value
 # and never to the environment one -- the path this tool tells operators to
 # PREFER, because argv is world-readable. Driven: GS_BTC_AMOUNT=0.123456789
 # accepted where --btc-amount 0.123456789 is refused.
 ("the BTC amount is validated before the environment supplies it",
  "GhostSpiral",
  "    resolve_wallet_password(args)\n    resolve_sensitive_inputs(args)",
  "    resolve_btc_amount(args)\n"
  "    resolve_wallet_password(args)\n    resolve_sensitive_inputs(args)",
  ["test_listed_bugs"]),

 # positive=True catches NaN, Infinity and 0; it does not catch 1e30, which is
 # finite, positive, and 39 digits against a 28-digit context -- so the first
 # fmt_btc() on it raises InvalidOperation. Same omission, same crash, as the
 # GS_EXIT_AMOUNT one already anchored above.
 ("GS_BTC_AMOUNT loses its ceiling again", "GhostSpiral",
  "        args.btc_amount = decimal_env(\"GS_BTC_AMOUNT\", _amt, positive=True,\n"
  "                                      max_value=BTC_ABSURD_TOTAL)",
  "        args.btc_amount = decimal_env(\"GS_BTC_AMOUNT\", _amt, positive=True)",
  ["test_listed_bugs"]),

 ("GS_SWAP_AMOUNTS loses its ceiling again", "thor_swap_preparer",
  "    args.amounts = [decimal_env(\"GS_SWAP_AMOUNTS\", x, positive=True,\n"
  "                                max_value=BTC_ABSURD_TOTAL)\n"
  "                    for x in str(_amts).split()]",
  "    args.amounts = [decimal_env(\"GS_SWAP_AMOUNTS\", x, positive=True)\n"
  "                    for x in str(_amts).split()]",
  ["test_listed_bugs"]),

 # oracle_prices was rounded to WHOLE UNITS, which is an absolute blur applied
 # to fields three orders of magnitude apart: xmr_usd (~165) lost 0.30% and
 # btc_usd (~65000) lost 0.00076%, pinning the instant the 10-minute timestamp
 # bucket exists to hide to about nine seconds.
 ("the oracle prices go back to an absolute blur that spares btc_usd",
  "exit_strategy_simulator",
  '        "oracle_prices": {k: str(coarsen_rate(Decimal(str(v))))\n'
  "                          for k, v in prices.items() if k != \"source\"},",
  '        "oracle_prices": {k: str(Decimal(str(v)).quantize(Decimal("1")))\n'
  "                          for k, v in prices.items() if k != \"source\"},",
  ["test_listed_bugs"]),

 # airgap_tx_signer writes accounts_count.txt one line after the
 # outputs_export.hex that IS swept, into the same directory, and no pattern
 # matched it -- the toolchain's only .txt artifact, invisible to the scan
 # whose extension whitelist was json/log/hex/key.
 ("the only .txt artifact drops off the wipe list again", "gs_common.py",
  '    "accounts_count.txt",\n', "",
  ["test_gitignore"]),

 # The scan that is supposed to make a new artifact "land here as a red check"
 # enumerated extensions, so a new extension was not unaccounted -- it was
 # never looked at.
 ("the artifact scan goes back to an extension whitelist",
  "tests/test_gitignore.py",
  "_ARTIFACT_LITERAL = _re.compile(r'\"([a-z0-9_]+\\.[a-z][a-z0-9]{0,5})\"')",
  "_ARTIFACT_LITERAL = _re.compile(r'\"([a-z0-9_]+\\.(?:json|log|hex|key))\"')",
  ["test_gitignore"]),

 # wipe_will_erase judges a directory by GS_ARTIFACT_DIR_PATTERNS; the function
 # whose only job is to EXPLAIN its answer used the FILE patterns for
 # everything, so a covered-but-misplaced staging directory was reported as
 # "both" -- "no name like yours is ever swept", the opposite of the truth.
 ("wipe_miss_reason goes back to judging a directory by the file patterns",
  "gs_common.py",
  "    pats = (GS_ARTIFACT_DIR_PATTERNS if res.is_dir()\n"
  "            else GS_ARTIFACT_FILE_PATTERNS)\n"
  "    return any(fnmatch.fnmatch(res.name, pat) for pat in pats)",
  "    return any(fnmatch.fnmatch(res.name, pat)\n"
  "               for pat in GS_ARTIFACT_FILE_PATTERNS)",
  ["test_opsec_guarantees", "test_gitignore"]),

 # --result-json is free-form like the two --outfiles that DO warn, and it
 # records the arrival AMOUNT in XMR. Nothing told an operator running the tool
 # by hand that the sweep would walk past it.
 ("receive_watch stops warning that its result file survives the wipe",
  "receive_watch",
  "    _p = Path(path)\n    if not wipe_will_erase(_p):",
  "    _p = Path(path)\n    if False:",
  ["test_receive_watch", "test_listed_bugs"]),

 # A bare mkdir is 0777 & ~umask -- measured 0755, and a real uid-65534 child
 # listed thor_pairs_*.json, wallet_*.json, the job log and the status file.
 ("the wake agent's artifact directory goes back to a bare mkdir",
  "gs_wake_agent",
  "    secure_mkdir(artifact_dir, narrow_existing=False)",
  "    artifact_dir.mkdir(parents=True, exist_ok=True)",
  ["test_wake_agent", "test_listed_bugs"]),

 # `tampered` only examines entries where i.sha is truthy; the summary line
 # counted every PRESENT blob and called them all OK. Driven: a two-entry
 # manifest with one hash stripped and that blob overwritten reported
 # "Manifest verification: 2/2 present blobs OK" and relayed it.
 ("a partially-hashed manifest is summarised as OK again",
  "broadcast_signed_xmr",
  "        if _unchecked:\n"
  '            integrity_log("broadcast", f"manifest_partial_hashes:{len(_unchecked)}")',
  "        if False:\n"
  '            integrity_log("broadcast", f"manifest_partial_hashes:{len(_unchecked)}")',
  ["test_broadcast"]),

 # _file_delivery_public swallowed six failure shapes into "" and the caller
 # then stated ONE of them as fact -- "it was minted before that field
 # existed" -- about files whose head had been edited.
 ("the delivery key's UNKNOWN branch goes back to guessing the cause",
  "gs_delivery_key",
  '    if not isinstance(head, dict) or "delivery_public" not in head:\n'
  '        return "", "absent"',
  '    if not isinstance(head, dict) or "delivery_public" not in head:\n'
  '        return "", "malformed"',
  ["test_listed_bugs"]),

 # A plan matching this batch, discarded for one unusable delay, left exactly
 # one line of output -- "No TX delays found" -- which reads as "there is no
 # plan", so the operator relays with no schedule instead of fixing a field.
 ("a rejected plan goes back to being discarded in silence",
  "broadcast_signed_xmr",
  "        for _name, (_pos, _val) in rejected:",
  "        for _name, (_pos, _val) in []:",
  ["test_broadcast"]),

 # `prices` is only populated when the price ALSO passes the (0, ABSURD] guard,
 # so an XMR entry quoting 0 / a negative / 1e30 was reported as an ABSENT
 # market -- sending the operator to look for one that was there.
 ("an unusable Bisq price goes back to being reported as a missing market",
  "exit_strategy_simulator",
  "        _want = \"XMR\" if \"xmr_btc\" not in prices else \"USD\"\n"
  "        if _want in seen_codes:",
  "        _want = \"XMR\" if \"xmr_btc\" not in prices else \"USD\"\n"
  "        if False:",
  ["test_listed_bugs"]),

 # The remedy was computed from the Bisq failure alone, so a run where
 # CoinGecko never got a packet back printed "Tor is not the problem".
 ("the oracle remedy goes back to ignoring CoinGecko's failure",
  "exit_strategy_simulator",
  '        + ("    Check Tor connectivity and retry." if _network and _cg_net else',
  '        + ("    Check Tor connectivity and retry." if _network else',
  ["test_listed_bugs"]),

 # The WRITER accepted what the READER refuses. airgap_tx_signer put `delay`
 # verbatim into both manifests and never validated it, so a value broadcast
 # rejects at relay time was carried across the air gap first -- after every
 # blob had been built and signed.
 ("the signer goes back to writing a delay the relay will refuse",
  "airgap_tx_signer",
  "        _dly = tx.get(\"delay\")\n"
  "        if _dly is not None and not delay_is_sane(_dly):",
  "        _dly = tx.get(\"delay\")\n"
  "        if False:",
  ["test_listed_bugs"]),

 # ...and the manifest validator is the second place it can arrive: a manifest
 # hand-edited between create and sign is invisible to the plan check.
 ("the signer's manifest validator goes back to ignoring the delay",
  "airgap_tx_signer",
  "        _d = entry.get(\"delay\")\n"
  "        if _d is not None and not delay_is_sane(_d):",
  "        _d = entry.get(\"delay\")\n"
  "        if False:",
  ["test_listed_bugs"]),

 # The plan fingerprint covers `delay`, but it is computed over the PLAN and
 # broadcast reads the MANIFEST -- so a manifest-only edit matched the
 # fingerprint perfectly and rewrote the relay schedule.
 ("a manifest-only delay edit goes back to matching the fingerprint",
  "airgap_tx_signer",
  "    if _dmis:\n"
  '        integrity_log("signer", f"manifest_delay_mismatch:{len(_dmis)}")',
  "    if False:\n"
  '        integrity_log("signer", f"manifest_delay_mismatch:{len(_dmis)}")',
  ["test_listed_bugs"]),

 # ANCHORED ON THE SOURCE, NOT ON THE CHECK. The first version of this mutated
 # the test back to searching the whole file -- and SURVIVED, correctly: while
 # the docstring DOES name gs_console, a file-wide search finds it too, so the
 # two spellings agree and the mutant is equivalent. This file's own rule is
 # that an equivalent mutant means the anchor is wrong, not that the guarantee
 # is untested.
 #
 # The guarantee is "install_signal_handlers' docstring names the two scripts
 # it does NOT cover". Mutating the docstring is what tests it, and it is also
 # the regression that would actually happen -- somebody tidying the docstring,
 # not somebody loosening the check. Under the old file-wide search this
 # mutation would have SURVIVED, because gs_console appears elsewhere in
 # gs_common.py; under the scoped one it is caught.
 ("install_signal_handlers goes back to claiming it covers every script",
  "gs_common.py",
  "    THAT IS NOT EVERY SCRIPT, and this docstring used to say it was -- \"the one\n"
  "    hook that reliably covers them all\". Two programs never call it, and they",
  "    It is the one hook that reliably covers them all. Two programs also have\n"
  "    their own, and they",
  ["test_listed_bugs"]),

 # ------------------------------------------------------------------
 #  Round: the operator's cut, and the minimum a UI may print
 # ------------------------------------------------------------------

 # The cut is deducted unconditionally but only the FAN-OUT branch pays it, so
 # --peel took 1.1% and paid nobody: the residue landed on the veil carrier and
 # the exit swept it to --exit-to.
 ("--usage-fee --peel goes back to charging a cut it never pays",
  "GhostSpiral",
  '    if getattr(args, "peel", False):\n        sys.exit(',
  '    if False:\n        sys.exit(',
  ["test_dag_entry"]),

 # A split cut is checked against the TOTAL and paid as N separate outputs,
 # each of which can be individually below the fee to move it.
 ("--usage-fee --split N goes back to a cut that may be unspendable per chunk",
  "GhostSpiral",
  '    if int(getattr(args, "split", 1) or 1) > 1:\n'
  "        sys.exit(\n"
  '            f"[!] --usage-fee with --split "',
  '    if False:\n'
  "        sys.exit(\n"
  '            f"[!] --usage-fee with --split "',
  ["test_dag_entry"]),

 # This branch used to sys.exit with "Nothing has been spent" -- true of
 # Monero, false of the deposit, which is already through ThorChain and sitting
 # on an address the swap memo names in a public OP_RETURN.
 ("the unspendable-cut branch goes back to aborting after the swap",
  "GhostSpiral",
  '        print(f"  [!] NO USAGE FEE TAKEN. {(pct * 100).normalize()}% of this "',
  '        sys.exit(f"  [!] NO USAGE FEE TAKEN. {(pct * 100).normalize()}% of this "',
  ["test_dag_entry"]),

 # The cut account was minted, paid, and mentioned nowhere -- and the wallet
 # balance is the only authoritative record that the operator was paid.
 ("the cut is taken again without telling the operator where it went",
  "GhostSpiral",
  '    print(f"  [*] USAGE FEE: {cut} XMR',
  '    _unused = (f"  [*] USAGE FEE: {cut} XMR',
  ["test_dag_entry"]),

 # A fixed cut address is the reuse this repo refuses by sys.exit in three
 # other places; minting per run is what removes the cross-run join key.
 ("the cut goes back to one account instead of a fresh one per run",
  "GhostSpiral",
  # Re-anchored: the two mints moved inside a try/except this turn, so a
  # wallet that refuses them waives the fee instead of killing a settled run.
  '        _acct = create_fresh_account(rpc, label="")',
  "        _acct = 0",
  ["test_dag_entry"]),

 # The distinctness staircase needs n(n-1)/2 DUST ticks -- 0.177 XMR at 60
 # wallets, more than the fundability floor asks for. A minimum derived from
 # the floor alone is short, in the direction that strands a run.
 ("the displayed minimum forgets the distinctness staircase",
  "GhostSpiral",
  "    ticks = Decimal(n * (n - 1) // 2) + Decimal(n)",
  "    ticks = Decimal(n)",
  ["test_dag_entry"]),

 # A cut worth exactly the fee to move it is worth nothing once moved.
 ("the cut spendability floor goes back to being one tick short",
  "GhostSpiral",
  "        need = max(need, (hop_fee_reserve(fee_xmr) + DUST_XMR) / usage_pct)",
  "        need = max(need, hop_fee_reserve(fee_xmr) / usage_pct)",
  ["test_dag_entry"]),

 # The fan-out funds wallets + randint(DECOY_MIN, DECOY_MAX), drawn at run
 # time, so a minimum computed from --wallets alone survives a lucky draw only.
 ("the displayed minimum forgets the decoys the operator does not choose",
  "GhostSpiral",
  "    n = w + DECOY_MAX",
  "    n = w",
  ["test_dag_entry"]),

 # The four money fields were the only inputs on the console page asking for a
 # quantity without stating one.
 ("the console stops telling the operator the minimum",
  "gs_console",
  '                "limits": limits_note(c["params"]),',
  '                "limits": "",',
  ["test_console"]),

 # The badge is the operator's only sight of the three numbers at the moment
 # they choose to spend -- the note is further up the page, above the fold.
 ("the spend buttons stop carrying the minimum, maximum and fee",
  "gs_console",
  '                "badge": limits_badge(c["params"])}))',
  '                "badge": ""}))',
  ["test_console"]),

 # ---- the usage fee is kept out of the exit by TWO locks -----------------
 #
 # The first is an omission: nothing puts the fee account in addr_index, so
 # _exit_account_list cannot name it. The second is this hold. Each mutation
 # below removes ONE of them, which is the only way to tell a live guard from
 # a guard that has been inert since it was written.

 # main() is where the pair produced in stage 4 meets the exit that must
 # refuse it. A producer and a consumer that are each correct in isolation is
 # not a wired pipeline -- the ENTRY hold proved that, twice.
 ("the fee pair never leaves main(), so the exit is never told to refuse it",
  "GhostSpiral",
  "                                 exit_fee_hold=([_fee_pair] if _fee_pair\n"
  "                                                else []),",
  "                                 exit_fee_hold=[],",
  ["test_dag_entry"]),

 ("_stage5_run drops the fee pair instead of folding it into the hold",
  "GhostSpiral",
  "        for _fp in (exit_fee_hold or ()):",
  "        for _fp in ():",
  ["test_exit_withdraw"]),

 # Riding on entry_pairs would classify the fee as the swap ENTRY, and every
 # one of ENTRY's remedies is wrong for it: no public memo names the fee, and
 # it is not value waiting to be mixed. Telling the operator to feed their own
 # fee back through a run spends the fee on fees.
 ("the fee is reported as a distribution change, losing its own remedy",
  "GhostSpiral",
  '        if pair in _fee_set:\n            return "usagefee"',
  "        if False:\n            return \"usagefee\"",
  ["test_exit_withdraw"]),

 # ---- the mint can fail, and the swap has already settled ----------------
 #
 # create_fresh_account raises rather than defaulting to account 0. Uncaught,
 # that takes main() down at stage 4 -- after the BTC is through ThorChain and
 # the XMR is on an address a public OP_RETURN names. Same outcome the
 # below-floor branch stopped producing; this was the door beside it.
 ("a wallet that will not mint the fee account kills the run again",
  "GhostSpiral",
  '        integrity_log("usagefee", "waived_mint_failed")',
  "        raise",
  ["test_dag_entry"]),

 # ---- the accounts no other warning reaches ------------------------------
 #
 # report_holdings says "SPEND THEM ONE ACCOUNT AT A TIME" over the run's
 # accounts, and the fee account is deliberately not one of them. Each fee is
 # a FIXED FRACTION of one deposit, so merging two does not merely link them,
 # it measures the runs behind them.
 ("the fee accounts go back to getting no spend-hygiene warning at all",
  "GhostSpiral",
  '    print(f"      SPEND IT ON ITS OWN. Every run mints another of these, and "',
  '    _unused = (f"      SPEND IT ON ITS OWN. Every run mints another of these, and "',
  ["test_dag_entry"]),

 # ---- labels are written INTO the wallet file ----------------------------
 #
 # paranoia_mode never deletes the wallet file; it is the only thing that can
 # still spend the money. So a label outlives every artifact wipe, and a
 # labelled fee account does the analyst's arithmetic for them.
 ("the fee account is labelled, and the label outlives every wipe",
  "GhostSpiral",
  '        _acct = create_fresh_account(rpc, label="")',
  '        _acct = create_fresh_account(rpc, label="usage fee")',
  ["test_dag_entry"]),

 # ---- /fee predates --usage-fee and answers about something else ---------
 #
 # It answers about the BITCOIN network fee and the swap's slippage floor. Now
 # that a thing called a usage fee exists, someone typing /fee to ask about
 # theirs gets a confident answer about something else, and silence about their
 # own reads as "not built". It is named there only to say it is not there --
 # this channel is designed on the assumption the transcript gets read, and the
 # rate is what divides a cash-out back into a deposit.
 # ---- the vault finds its own money, and leaves nothing behind ----------
 #
 # /withdraw used to take a 4-hex handle naming a bundle a /depo had minted,
 # so only money that arrived through this tool's own deposit flow could be
 # withdrawn -- and the operator had to remember which label named which pile.
 # The machine holding the wallet is the one that can see where the money is.
 ("the withdraw job goes back to demanding a handle", "gs_wake_proto.py",
  '        "schema": {"exit_to": _xmr_address_field},',
  '        "schema": {"handle": _handle_field, "exit_to": _xmr_address_field},',
  ["test_wake_agent"]),

 # Summing subaddresses would mean a first transaction spending inputs from
 # all of them -- permanent public proof they share an owner, which is what
 # the rest of the pipeline spends hours avoiding.
 ("the withdrawal merges every funded output into one spend", "gs_wake_agent",
  "                if best is None or _amt > best[3]:",
  "                if True:",
  ["test_wake_agent"]),

 # A locked balance cannot be spent, and a mix planned around one fails
 # partway with money already moved.
 ("a withdrawal is planned around a locked balance", "gs_wake_agent",
  '                _amt = _sub.get("unlocked_balance")',
  '                _amt = _sub.get("balance")',
  ["test_wake_agent"]),

 # gs_withdraw_*.json matched NOTHING in GS_ARTIFACT_FILE_PATTERNS, so the
 # pointer would have sat in the artifact directory naming an account of this
 # wallet through every paranoia_mode run.
 ("the withdraw pointer is named so the wipe misses it", "gs_wake_agent",
  '        bundle = str(artifact_dir / f"wallet_withdraw_{handle}.json")',
  '        bundle = str(artifact_dir / f"gs_withdraw_{handle}.json")',
  ["test_wake_agent"]),

 # ---- the budget has to fit the WORST case, not the median --------------
 #
 # It was 14400s (4h), chosen against estimate_runtime's "~3.2h" -- a MEDIAN.
 # --hop-delay draws 60-300s about thirty times; the slow end is ~4.5h. A run
 # that drew high went over, and over budget is not a late report: run_child
 # SIGTERMs the process group and then SIGKILLs it, mid-mix, with the money
 # already moving.
 ("the spending budget goes back to fitting only the median",
  "gs_wake_proto.py",
  '        "budget_s": 21600,',
  '        "budget_s": 14400,',
  ["test_wake_agent"]),

 # At 20 wallets the same job takes 4.2h and at 40 it takes 6.2h. Leaving the
 # count to another file's default makes whether the mix is killed mid-spend a
 # property nobody would think to check.
 ("the mix inherits its wallet count from another file's default",
  "gs_wake_agent",
  '                 "--wallets", str(WITHDRAW_WALLETS),\n',
  "",
  ["test_wake_agent"]),

 # ---- the spending job has to be able to SIGN ---------------------------
 #
 # GhostSpiral's Round 1 signs with `--wallet-file <path>` and a password in
 # the environment. BOTH have defaults, so composing neither does not fail
 # loudly: the mix plans, veils, relays a fan-out, waits out its confirmations,
 # and dies HOURS later at "produced no signed TX files" -- with the money
 # already moved on-chain.
 ("the mix is composed without a wallet to sign with", "gs_wake_agent",
  '                 "--wallet-file", str(_wf),\n',
  "",
  ["test_wake_agent"]),

 ("a keyfile with no wallet file is accepted anyway", "gs_wake_agent",
  '        if not _wf:\n            raise Refused(',
  "        if False:\n            raise Refused(",
  ["test_wake_agent"]),

 # Every child of every job inherited the agent's whole environment. Harmless
 # until a GS_ variable is needed -- and then it hands the spend password to
 # thor_swap_preparer and create_receive_wallet.
 ("every child inherits the agent's whole environment again",
  "gs_wake_agent",
  '    for _k in [k for k in env if k.startswith("GS_")]:\n'
  "        env.pop(_k, None)",
  "    pass",
  ["test_wake_agent"]),

 ("the spending step is not handed the password it needs", "gs_wake_agent",
  '            env_extra["GS_WALLET_PASSWORD"] = os.environ.get(\n'
  '                "GS_WALLET_PASSWORD", "")',
  "            pass",
  ["test_wake_agent"]),

 # --allow-withdraw without --wallet-file writes a keyfile whose withdraw job
 # relays a fan-out and then fails at signing.
 ("pairing accepts a withdraw keyfile that cannot sign", "gs_wake_keys",
  "    if args.allow_withdraw and not args.wallet_file:",
  "    if False:",
  ["test_wake_agent"]),

 # ---- the one job that spends -------------------------------------------
 #
 # /withdraw is the first job that drives a spending tool, carries free text,
 # and can move money. Every one of these gates is the only thing between a
 # stolen bot token and a withdrawal.

 # The keyfile decides, and an old keyfile means no.
 ("a spending job runs without the keyfile allowing it", "gs_wake_agent",
  '        if not key.get("allow_withdraw"):',
  "        if False:",
  ["test_wake_agent"]),

 # A mix under the shipped 9300s backstop is the vault powering off mid-round,
 # which GhostSpiral says it cannot recover from automatically.
 ("a spending job runs under a backstop too short for it", "gs_wake_agent",
  "        if not _extend_deadman(_need):",
  "        if False:",
  ["test_wake_agent"]),

 # Arm, VERIFY, then disarm. systemd-run can exit 0 having queued a job that
 # never starts, and that check is all that stands between a four-hour spend
 # and no backstop at all.
 ("the longer backstop is assumed armed rather than verified",
  "gs_wake_agent",
  '        if not (is_active or unit_is_active)(f"{DEADMAN_EXT_UNIT}.timer"):\n'
  "            return False",
  "        if False:\n            return False",
  ["test_wake_agent"]),

 # The destination is the first operator-chosen string to cross the boundary.
 # In the environment it cannot become a flag; on an argv it is world-readable
 # for the whole run.
 ("the withdrawal address goes on the argv again", "gs_wake_agent",
  '            env_extra["GS_EXIT_TO"] = _dest',
  "            argv.append(_dest)",
  ["test_wake_agent"]),

 # The argv template interpolates `bundle`, and the resolver that fills it in
 # lives in another function. Driven when this was missing: the composed
 # command was `--receive-wallet None` -- a mix pointed at a bundle that does
 # not exist, on the one job that spends.
 ("the spending job runs against an unresolved bundle", "gs_wake_agent",
  # Re-anchored: withdraw no longer resolves a handle at all -- the vault
  # finds its own funded output. What must not regress is that it REFUSES
  # rather than mixing against an empty wallet.
  "        if not _found:",
  "        if False:",
  ["test_wake_agent"]),

 # The gate that refuses a flag, a path, a URL or a shell fragment.
 ("the address gate stops refusing anything", "gs_wake_proto.py",
  "    if any(c not in _B58_XMR for c in v):",
  "    if False:",
  ["test_wake_protocol"]),

 ("the address gate stops checking the length", "gs_wake_proto.py",
  "    if len(v) not in (95, 106):",
  "    if False:",
  ["test_wake_protocol"]),

 # The split that keeps "unreachable from every job" a testable property of
 # FORBIDDEN_TOOLS rather than "unreachable except sometimes".
 ("the mix becomes reachable from an ordinary job", "gs_wake_proto.py",
  '        if _gated and _name not in SPENDING_JOBS:\n            return False',
  "        if False:\n            return False",
  ["test_wake_protocol"]),

 # /withdraw with the address on the same line skips the confirm and puts the
 # destination in the transcript attached to the command.
 ("/withdraw takes the address on the command line", "gs_telegram_pager",
  '        if arg:\n            return "", {}, "just /withdraw — it asks"',
  '        if False:\n            return "", {}, "just /withdraw — it asks"',
  ["test_depo_wizard"]),

 # A rejected near-miss of the operator's own destination is the same
 # disclosure as the address itself.
 ("a rejected address is echoed back into the transcript",
  "gs_telegram_pager",
  '                self.send(chat_id, "no: bad address. Cancelled.")',
  '                self.send(chat_id, f"no: bad address: {_a}. Cancelled.")',
  ["test_depo_wizard"]),

 # ---- a phase outranks the outcome ---------------------------------------
 #
 # Three gates each dropped it, and fixing any one alone changes nothing --
 # which is why a /watch whose money was still confirming reported
 # "watch: failed." after the vault had already powered off.
 ("a non-zero rc is a failure for watch again", "gs_wake_agent",
  '        if rc != 0 and job in ("swap_status", "watch") and not hard:',
  '        if rc != 0 and job == "swap_status" and not hard:',
  ["test_plain_slip"]),

 ("the phase is thrown away unless the job finished", "gs_wake_agent",
  '            "phase": phase}',
  '            "phase": phase if done else ""}',
  ["test_plain_slip"]),

 ("a watch reports the answer a probe left behind hours ago", "gs_wake_agent",
  '    if job in ("swap_status", "watch"):\n'
  "        try:\n"
  "            (artifact_dir / STATUS_FILE).unlink()",
  '    if job == "swap_status":\n'
  "        try:\n"
  "            (artifact_dir / STATUS_FILE).unlink()",
  ["test_plain_slip"]),

 ("the pager only renders a phase on a finished job", "gs_telegram_pager",
  "        if _early and out != \"done\":",
  "        if False:",
  ["test_plain_slip"]),

 # ---- the wizard is the only path, and the card holds no map -------------
 #
 # `/depo 2` was one keystroke from a wake and a real quote, which makes the
 # confirm the wizard exists for optional -- and it put the digit in the
 # transcript attached to the word, permanently.
 ("/depo goes back to waking on one keystroke", "gs_telegram_pager",
  '        if arg:\n            return "", {}, "just /depo — it asks"\n'
  '        return "", {}, "depo_wizard"',
  '        if not arg:\n            return "", {}, "depo_wizard"\n'
  "        if not arg.isdecimal():\n"
  '            return "", {}, "slot 0-7"\n'
  "        s = int(arg)\n"
  "        if not 0 <= s <= 7:\n"
  '            return "", {}, "slot must be 0-7"\n'
  '        return "receive_and_quote", {"amount_slot": s}, ""',
  ["test_depo_wizard"]),

 # The one file the pager persists held a float per poke: the exact second the
 # operator asked for a quote, for every quote in 24 hours, on the SD card.
 ("the SD card holds exact wake timestamps again", "gs_telegram_pager",
  "    STAMP_BUCKET_S = 300",
  "    STAMP_BUCKET_S = 1",
  ["test_telegram_pager"]),

 # systemctl prints Description to anyone who can read the unit.
 ("the Pi's unit names the toolchain in systemctl again",
  "systemd/gs-telegram-pager.service.example",
  "Description=Relay",
  "Description=GhostSpiral Telegram pager (Pi side)",
  ["test_telegram_pager"]),

 # Without a UMask the log is created world-readable on the one box that is
 # meant to hold nothing.
 ("the Pi's log goes back to world-readable",
  "systemd/gs-telegram-pager.service.example",
  "UMask=0077",
  "# UMask unset",
  ["test_telegram_pager"]),

 # ---- three more things the chat did not need to say ---------------------
 #
 # /status printed the poke count for the last 24 hours and busy True/False:
 # how many deposits were started today, and whether the machine is powered on
 # at this moment. Both permanent, in a transcript, on a command whose whole
 # job is to answer "can I send one".
 ("/status discloses the wake count and the power state again",
  "gs_telegram_pager",
  "            _why = self.limits.why_not()\n"
  "            self.send(cid, _why if _why\n"
  '                      else ("wait" if self.busy.locked() else "ready"))',
  '            self.send(cid, f"pokes in last 24h: {len(self.limits.recent())}/"\n'
  '                           f"{self.limits.daily_cap}\\n"\n'
  '                           f"busy: {self.busy.locked()}")',
  ["test_telegram_pager"]),

 ("every typo reprints the whole command list again", "gs_telegram_pager",
  '            self.send(cid, f"no: {err}")',
  '            self.send(cid, f"no: {err}\\n\\n{HELP}")',
  ["test_telegram_pager"]),

 # OPSEC_SETUP section 5 step 5 specifies "depo ready · slip A3F1".
 ("the chat goes back to the machine's own job identifiers",
  "gs_telegram_pager",
  '    "receive_and_quote": "depo",',
  '    "receive_and_quote": "receive_and_quote",',
  ["test_sealed_slip"]),

 # Every wake serves 5-20 min of jitter BEFORE the job starts, so a "~5 min"
 # round trip understated it by two to seven times.
 ("/check's quoted time forgets the jitter it always waits",
  "gs_telegram_pager",
  '    "/check <h>  has it arrived? (10-25 min)\\n"',
  '    "/check <h>  has it arrived? (~5 min)\\n"',
  ["test_telegram_pager"]),

 # ---- chat text that arrives through a variable --------------------------
 #
 # A source scan for literals at send() call sites cannot see a string that
 # gets there in a variable. Two did.
 ("the rate-limit refusal describes the wake architecture again",
  "gs_telegram_pager",
  '            return f"wait {int(self.min_interval - gap)}s"',
  '            return (f"rate limited, {int(self.min_interval - gap)}s left "\n'
  '                    f"(courtesy limit; the vault\'s own 24h budget is the "\n'
  '                    f"real one)")',
  ["test_telegram_pager"]),

 # gs_doorbell refuses a bind with the Pi's own listen host and port in the
 # text, and poke() forwards that exception straight to Telegram.
 ("the Pi's listen address reaches the chat again", "gs_telegram_pager",
  '    out = re.sub(r"\\b(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9-]"',
  '    out = re.sub(r"(?!x)x" or r"\\b(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9-]"',
  ["test_telegram_pager"]),

 # ---- four defects that broke no existing check --------------------------

 # limits.record() and integrity_log() both write the SD card and both ran
 # after acquire() and outside the release guard. A full card leaves the wake
 # lock held by nobody for the life of the process.
 ("a failed state write wedges the wake lock forever", "gs_telegram_pager",
  "        try:\n            self.limits.record()\n"
  '            integrity_log("pager", f"poke:{job}")',
  '        self.limits.record()\n        integrity_log("pager", f"poke:{job}")\n'
  "        try:",
  ["test_telegram_pager"]),

 # run() reads upd.get("update_id") in the FOR HEADER, outside the per-update
 # try, so one bare string in the batch kills the process -- and the offset was
 # never advanced past it, so it crash-loops.
 ("a malformed update element kills the pager", "gs_telegram_pager",
  "        return [u for u in out if isinstance(u, dict)]",
  "        return out",
  ["test_telegram_pager"]),

 # The offset is what confirms an update. One that can never advance it is
 # redelivered on every poll, so handling it means acting on one message
 # forever.
 ("an update with no usable id is handled on every poll, forever",
  "gs_telegram_pager",
  "                if isinstance(uid, int) and not isinstance(uid, bool):",
  "                if True:",
  ["test_telegram_pager"]),

 # "²".isdigit() is True and int("²") RAISES. The wizard documents this fix;
 # parse_command never got it, so a typo escaped as a ValueError and the
 # operator got no reply at all.
 ("parse_command goes back to isdigit, which int() does not accept",
  "gs_telegram_pager",
  "            if not arg.isdecimal():\n"
  '                return "", {}, "count must be a number 1-4"',
  "            if not arg.isdigit():\n"
  '                return "", {}, "count must be a number 1-4"',
  ["test_telegram_pager"]),

 # receive_watch exits non-zero on timeout, so a watch that ran out of time was
 # reported as "watch: failed." -- money still in flight, called a failure.
 ("a watch that ran out of time is a failure again", "gs_wake_agent",
  '                 "--timeout-min", "110",',
  '                 "--timeout-min", "110"] + [] or [',
  ["test_wake_agent"]),

 ("only swap_status may report a phase again", "gs_wake_agent",
  '    if job not in ("swap_status", "watch"):',
  '    if job != "swap_status":',
  ["test_wake_agent"]),

 # ---- burn after reading ------------------------------------------------
 #
 # Making the replies boring was the first half; removing them afterwards is
 # the second. Neither replaces the other.
 ("the operator's own commands are no longer tracked for deletion",
  "gs_telegram_pager",
  "        _mid = msg.get(\"message_id\")\n"
  "        if isinstance(_mid, int) and not isinstance(_mid, bool):\n"
  "            self.burn.append((cid, _mid, time.time()))",
  "        _mid = msg.get(\"message_id\")",
  ["test_telegram_pager"]),

 ("a refused delete is retried on every tick, forever, over Tor",
  "gs_telegram_pager",
  "            if self.delete_message(cid, mid):\n                gone += 1\n        self.burn = keep\n        return gone",
  "            if self.delete_message(cid, mid):\n                gone += 1\n            else:\n                keep.append((cid, mid, sent))\n        self.burn = keep\n        return gone",
  ["test_telegram_pager"]),

 # A --burn-after past Telegram's window never fires, so the chat only LOOKS
 # like it is being emptied.
 ("a burn-after that can never fire is accepted instead of refused",
  "gs_telegram_pager",
  "    if args.burn_after > TG_DELETE_WINDOW_S:",
  "    if False:",
  ["test_telegram_pager"]),

 # The signal handler must not do network I/O: it runs between bytecodes and
 # can arrive inside safe_post.
 ("the burn signal does the work inside the handler", "gs_telegram_pager",
  "        self.burn_now = True",
  "        self.burn_all()",
  ["test_telegram_pager"]),

 # ---- chat text that lives in another file is still chat text ------------
 #
 # PHASE_LINES are defined in gs_wake_proto and sent verbatim by the pager
 # (`f"{h}: {PHASE_LINES.get(phase, phase)}"`). The source-level guard that
 # strips machine names from the pager's replies read literals in
 # gs_telegram_pager and could not see them: two said "check it on the vault"
 # and "the vault's wallet is not scanning" -- the operator's own hardware,
 # named in the readable surface, on the two answers most asked for when
 # something has gone wrong.
 ("a phase line names the operator's machine in the chat again",
  "gs_wake_proto.py",
  '    "stuck": "not scanning, so this says NOTHING about your money. Check.",',
  '    "stuck": "the vault\'s wallet is not scanning, so this says NOTHING "\n'
  '             "about your money. Check the vault.",',
  ["test_depo_wizard"]),

 # "Done." is about the SWAP, and shortening it to "Done" changed which noun.
 # The mix has not run; the money is sitting un-mixed; the operator is reading
 # the surface they check most.
 ("the landed line claims the whole job is finished", "gs_wake_proto.py",
  '    "landed": "landed and spendable. The swap is done.",',
  '    "landed": "landed and spendable. Done.",',
  ["test_plain_slip"]),

 # ---- the bot says the answer and stops -----------------------------------
 #
 # Two drafts explained instead of answering: where each knob really lives, why
 # it is not settable, what loosening it would cost -- and, worst, a sentence
 # saying the omission was deliberate because the transcript is assumed read.
 # Every one of those is a description of the arrangement, written permanently
 # into the readable surface, bought by telling the operator what they know.
 ("/fee goes back to explaining instead of answering", "gs_telegram_pager",
  'FEE_ANSWER = f"{USAGE_FEE_LABEL} usage fee."',
  'FEE_ANSWER = f"{USAGE_FEE_LABEL} usage fee. Set at the vault when you run '
  'the mix; this channel deliberately cannot read or change it."',
  ["test_depo_wizard"]),

 ("the help text goes back to describing the setup", "gs_telegram_pager",
  '    "Memo goes in an OP_RETURN — desktop wallet, not a phone."',
  '    "Memo goes in an OP_RETURN — desktop wallet, not a phone.\\n"\n'
  '    "What comes back depends on the VAULT\'s keyfile: a handle, a sealed "\n'
  '    "slip for gs_unseal, or the address in the clear."',
  ["test_depo_wizard"]),

 ("the confirm names the machine it is about to wake", "gs_telegram_pager",
  '            self.send(chat_id, f"slot {c.slot} — confirm.\\n\\n{q}")',
  '            self.send(chat_id, f"slot {c.slot} — this will WAKE THE VAULT "\n'
  '                               f"and quote a swap.\\n\\n{q}")',
  ["test_depo_wizard"]),

 # The label is copied rather than imported (the phone-side box has no reason
 # to carry the pipeline), so the copy is what can drift.
 ("the rate the bot prints drifts from the rate charged",
  "gs_telegram_pager",
  'USAGE_FEE_LABEL = "1.1%"',
  'USAGE_FEE_LABEL = "1%"',
  ["test_depo_wizard"]),

 # ---- the doc's list of env-carried values must be the code's list -------
 #
 # OPSEC_SETUP's paragraph confesses that GS_EXIT_TO "was missing from that
 # list for as long as the list existed, and the sentence above was false
 # because of it". The same drift then happened twice more, silently:
 # GS_EXPECT_TOTAL_XMR and the two usage-fee variables were added to
 # secret_env and never to the doc. Derived from the code now, so it cannot.
 ("the env-carried list goes back to being a hand-written snapshot",
  "gs_console",
  '    if params.get("usage_fee") and params.get("usage_fee_pct"):\n'
  '        env["GS_USAGE_FEE_PCT"] = str(params["usage_fee_pct"])',
  '    if params.get("usage_fee") and params.get("usage_fee_pct"):\n'
  '        env["GS_UNDOCUMENTED_SECRET"] = str(params["usage_fee_pct"])',
  ["test_env_leaks"]),

 # ---- the only durable pointer to the operator's own money ---------------
 #
 # plan_usage_fee prints the account and subaddress ONCE, in stage 4. Nothing
 # else carries it: the fee account is kept out of addr_index (so the exit
 # cannot sweep it), which keeps it out of report_holdings; the plan file has
 # the address but not the index, and a completed run wipes that plan; the
 # integrity chain carries structure only. gs_console keeps child output in a
 # 5000-line ring and drops 1500 at a time, so on a long run that one line goes.
 ("the run never restates where the usage fee landed", "GhostSpiral",
  '        integrity_log("usagefee", "restated_at_end")',
  "        return",
  ["test_units"]),

 # BEFORE the sys.exit, deliberately: a fee taken in stage 4 survives a run
 # that fails in stage 5, and that is the run with the longest scrollback.
 ("the fee reminder is lost on exactly the runs that need it", "GhostSpiral",
  "    if fee_pair:\n"
  '        integrity_log("usagefee", "restated_at_end")',
  "    if fee_pair and not incomplete:\n"
  '        integrity_log("usagefee", "restated_at_end")',
  ["test_units"]),

 ("main() stops handing the fee pair to the final report", "GhostSpiral",
  "                          fee_pair=_fee_pair,",
  "                          fee_pair=None,",
  ["test_dag_entry"]),

 # ---- a static fee address inside this wallet is the exit's to sweep -----
 #
 # _exit_account_list = addr_index's accounts + change_accounts + bal_account,
 # and bal_account is account 0 in send mode -- the wallet's PRE-EXISTING
 # primary account, which the run did not make. _funded_subaddresses walks
 # every subaddress of it. So "an address this run did not create" is not the
 # same as "an address the exit will not touch", and the likeliest paste of all
 # is the one it gets wrong.
 ("a static fee address inside the wallet is paid and then swept out",
  "GhostSpiral",
  "        _own = _wallet_owns_address(rpc, addr)",
  "        _own = None",
  ["test_dag_entry"]),

 # An error from get_address_index is what a REAL wallet answers for a foreign
 # address, so it must mean "not ours". Treating it as ours waives the fee on
 # every correct configuration.
 ("a foreign fee address is mistaken for one of this wallet's",
  "GhostSpiral",
  "    except Exception:                                        # noqa: BLE001\n"
  "        return None\n"
  '    _ix = (res or {}).get("index") if isinstance(res, dict) else None',
  "    except Exception:                                        # noqa: BLE001\n"
  "        return (0, 0)\n"
  '    _ix = (res or {}).get("index") if isinstance(res, dict) else None',
  ["test_dag_entry"]),

 # ---- the page has no masker, and it was rendering 48 of 95 characters ---
 #
 # /api/preview fires on every keystroke, and every prefix of a CORRECT address
 # fails the regex -- so this is ordinary typing, not an error path. The exit
 # list shows 16 and scrub_address shows 16; this showed 48, the longest
 # disclosure of an address anywhere in the toolchain.
 ("a rejected address is echoed back into the DOM at full length",
  "gs_console",
  '                    errs.append(f"{k} is not a valid {k.replace(\'_\', \' \')}: "\n'
  '                                f"{s[:16]}…")',
  '                    errs.append(f"{k} is not a valid {k.replace(\'_\', \' \')}: "\n'
  '                                f"{s[:48]}")',
  ["test_console"]),

 ("address fields go back onto the generic echo branch", "gs_console",
  '    "usage_fee_address": ("addr_re", XMR_RE),',
  '    "usage_fee_address": ("re", XMR_RE),',
  ["test_console"]),

 # ---- the public output count must match what an analyst counts ---------
 #
 # The fan-out notice quoted the MIX destination count while --usage-fee builds
 # one more output than that. This is the paragraph whose entire subject is
 # that the output count is public, so the operator has nothing to check the
 # figure against -- an off-by-one there is the one wrong number they cannot
 # catch.
 ("the announced fan-out output count forgets the fee output", "GhostSpiral",
  "    _real = int(n_outputs) + (1 if fee_out else 0)",
  "    _real = int(n_outputs)",
  ["test_dag_entry"]),

 # --peel and --usage-fee are refused together (the peel branch has no fee
 # destination and would deduct without paying). Advising the switch without
 # saying that sends the operator to a sys.exit on their next run.
 ("the shape notice offers a --peel run that will be refused", "GhostSpiral",
  '        print("      NOT ON THIS RUN, though: --peel and --usage-fee are "',
  '        _unused = ("      NOT ON THIS RUN, though: --peel and --usage-fee are "',
  ["test_dag_entry"]),

 # ---- the rate is the divisor, and argv is where it used to sit ----------
 #
 # /proc/<pid>/cmdline is 0444, every account on the host, for the life of the
 # run. A local reader sees argv and NOT the amounts -- those are inside RingCT
 # and inside plan files under a 0700 directory -- so argv was the ONLY
 # disclosure of the number that turns an observed cash-out back into a
 # deposit. GhostSpiral routes the rate through env_or_argv for exactly this
 # reason; the console handed it straight back.
 ("the console publishes the fee rate to ps again", "gs_console",
  '    if p.get("usage_fee"):\n        a.append("--usage-fee")',
  '    if p.get("usage_fee"):\n        a.append("--usage-fee")\n'
  '    if p.get("usage_fee_pct"):\n'
  '        a += ["--usage-fee-pct", str(p["usage_fee_pct"])]',
  ["test_console"]),

 # An env-supplied rate IS "skim" to resolve_usage_fee -- env is the preferred
 # channel, so requiring the argv flag too would defeat having it. Drop the
 # checkbox from this gate and a rate left in the field makes the run skim
 # while the page shows no fee at all.
 ("a rate left in the field skims with the box unticked", "gs_console",
  '    if params.get("usage_fee") and params.get("usage_fee_pct"):',
  '    if params.get("usage_fee_pct"):',
  ["test_console"]),

 ("the fee subaddress is labelled, which the wallet file also keeps",
  "GhostSpiral",
  '        addr, _idx = rpc.new_subaddress_indexed(account_index=_acct, label="")',
  '        addr, _idx = rpc.new_subaddress_indexed(account_index=_acct,\n'
  '                                                label="usage fee")',
  ["test_dag_entry"]),

]


#: The mutation sweep's copies must be TRAVERSABLE by an unprivileged user.
#:
#: tempfile.mkdtemp() is 0700, and several checks in test_listed_bugs fork a
#: child that drops to uid 65534 and then works under the repo's cwd -- the
#: whole point of them, because uid 0 ignores the write bit and that is what
#: hid the defect they cover. In a 0700 parent that child cannot traverse in
#: and every one of them fails with PermissionError(13). Measured: the suite is
#: green in place and 284/3 in a copy, for no reason but the mode of a
#: directory two levels up.
#:
#: The sweep's premise is that the copy behaves like the original. 0755 on the
#: temp root is what makes that true; the repo inside keeps whatever modes
#: copytree gave it.
def _traversable_tmp(prefix):
    tmp = tempfile.mkdtemp(prefix=prefix)
    os.chmod(tmp, 0o755)
    return tmp


def run(idx, name, fname, find, repl, suites):
    tmp = _traversable_tmp(f"mutg5_{idx}_")
    dst = os.path.join(tmp, "repo")
    # .git IS COPIED, and leaving it out silently invalidated five anchors.
    #
    # test_gitignore shells out to `git check-ignore` and `git ls-files`. Both
    # need a repository, so in a copy without .git the suite went red 62 checks
    # deep BEFORE any mutation was applied -- and run() decides CAUGHT purely
    # from "did this suite report failures", so every anchor naming it came
    # back CAUGHT whatever the mutation did. Measured on an unmutated copy:
    # 30 passed, 62 failed. Two of those anchors predate this and had been
    # reporting a verdict they had not earned.
    #
    # It costs 8.2 MB per mutation and is removed with the rest of the tree.
    # The pre-flight below is the general answer; this is the specific one.
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", "integrity_chain.log*"))
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
    caught, verdicts, crashed = False, [], False
    for suite in suites:
        try:
            p = subprocess.run([sys.executable, f"tests/{suite}.py"], cwd=dst,
                               capture_output=True, text=True, timeout=900)
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            # A HUNG SUITE IS NOT A CATCH EITHER, and letting the exception
            # escape would abandon the whole sweep at whichever mutation
            # happened to hang.
            out = ""
            verdicts.append(f"{suite}=TIMEOUT")
            crashed = True
            continue
        m = re.findall(r"(\d+) passed, (\d+) failed", out)
        if not m:
            verdicts.append(f"{suite}=NO-RESULT")
            crashed = True
            continue
        failed = int(m[-1][1])
        verdicts.append(f"{suite}={'RED' if failed else 'green'}({failed})")
        if failed:
            caught = True
    shutil.rmtree(tmp, ignore_errors=True)
    # A CRASHED SUITE IS NOT A SURVIVOR, AND SAYING SO MATTERS. This reported
    # "*** SURVIVED ***" for a suite that never ran -- a mutation that made the
    # source syntactically invalid, so the test file died on import and printed
    # no RESULT line. Both outcomes fail the sweep, so the tally was not wrong,
    # but the WORD was: SURVIVED means "the tests ran and noticed nothing",
    # which sends you to write a test that already exists. NO-RESULT means "the
    # tests could not run", which sends you to fix the mutation. This file's own
    # header has drawn that distinction from the start and the code did not.
    if crashed and not caught:
        tag, verdict = "*** NO-RESULT ***", "NO-RESULT"
    elif caught:
        tag, verdict = "CAUGHT", "CAUGHT"
    else:
        tag, verdict = "*** SURVIVED ***", "SURVIVED"
    print(f"[{idx:2d}] {tag:17s} {name}\n       {'  '.join(verdicts)}")
    return verdict


def control(suites) -> dict:
    """Run each suite on an UNMUTATED copy. Returns {suite: failures}.

    A SUITE THAT IS ALREADY RED PROVES NOTHING ABOUT A MUTATION. run() decides
    CAUGHT from `failed = int(m[-1][1])` -- "did this suite report failures" --
    which is only evidence if the suite reports none without the mutation. It
    did not: the copy excluded .git, `git check-ignore` cannot run without a
    repository, and test_gitignore came back 30 passed / 62 failed on a
    pristine tree. Five anchors named that suite and all five reported CAUGHT
    for a reason that had nothing to do with what they mutated.

    This is the same distinction the header already draws twice -- SKIP is not
    a pass, NO-RESULT is not a survivor -- in the one direction nobody had
    written down: PRE-RED is not a catch. Fixing the .git copy fixes today's
    instance; this catches the next one, whatever causes it.

    Run ONCE for the whole sweep rather than per mutation: the answer cannot
    depend on which mutation is pending, and per-mutation controls would double
    a sweep that already takes an hour.
    """
    tmp = _traversable_tmp("mutg5_control_")
    dst = os.path.join(tmp, "repo")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", "integrity_chain.log*"))
    out = {}
    for suite in sorted(suites):
        try:
            p = subprocess.run([sys.executable, f"tests/{suite}.py"], cwd=dst,
                               capture_output=True, text=True, timeout=900)
            m = re.findall(r"(\d+) passed, (\d+) failed", p.stdout + p.stderr)
            out[suite] = int(m[-1][1]) if m else -1
        except subprocess.TimeoutExpired:
            out[suite] = -1
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def anchors_ok(selection) -> list:
    """Every anchor, read against the PRISTINE source. Returns the rotten ones.

    Milliseconds, and it runs FIRST -- which is the whole point. The tally at
    the bottom of this file already exits 1 on a SKIP, but only after every
    mutation has been applied, copied and run: hours, for a fact that is
    available before the first copy is made. So nobody ever paid to learn it,
    and anchors rotted in the dark.

    Five had, when this was written: two named a print() whose text had been
    renamed ("CUT" -> "USAGE FEE"), two named lines that had since grown a
    fourth held-output kind, and one named a dict entry that gained a sibling.
    All five reported SKIP, all five would have been read as coverage, and the
    guarantees behind them -- including "the operator is told where their fee
    went" -- were unswept for two turns.

    Reads each file ONCE and counts: an anchor that matches zero times names
    source that no longer exists, and one that matches twice mutates a place
    the author did not choose.
    """
    cache, rotten = {}, []
    for i, mut in selection:
        _name, _file, _find = mut[0], mut[1], mut[2]
        if _file not in cache:
            cache[_file] = open(os.path.join(REPO, _file)).read()
        n = cache[_file].count(_find)
        if n != 1:
            rotten.append((i, n, _name, _file))
    return rotten


if __name__ == "__main__":
    only = set(sys.argv[1:])
    _sel = [m for i, m in enumerate(MUTATIONS) if not only or str(i) in only]
    # BEFORE the control run, and long before the first repo copy: a rotten
    # anchor is a guarantee that goes unswept, and finding that out at the end
    # of a multi-hour sweep is how five of them survived two turns.
    _rot = anchors_ok([(i, m) for i, m in enumerate(MUTATIONS)
                       if not only or str(i) in only])
    if _rot:
        print(f"[!] {len(_rot)} anchor(s) no longer match the source exactly "
              f"once. Each is a guarantee this sweep would report SKIP for, "
              f"i.e. NOT swept:")
        for _i, _n, _nm, _f in _rot:
            print(f"    #{_i} matches {_n}x in {_f}: {_nm}")
        print("    Re-anchor them against the current source before running "
              "the sweep; a tally with SKIPs in it is not coverage.")
        sys.exit(1)
    _suites = {s for m in _sel for s in m[4]}
    print(f"[anchors] all {len(_sel)} anchor(s) match the source exactly once")
    print(f"[control] {len(_suites)} suite(s) on an UNMUTATED copy — a suite "
          f"that is already red cannot catch anything")
    _ctl = control(_suites)
    _prered = {k: v for k, v in _ctl.items() if v != 0}
    for _s in sorted(_ctl):
        if _ctl[_s] == 0:
            _v = "green"
        elif _ctl[_s] < 0:
            _v = "NO-RESULT -- the suite did not report at all"
        else:
            _v = f"RED({_ctl[_s]}) -- PRE-RED"
        print(f"           {_s}: {_v}")
    if _prered:
        print(f"\n[!] {len(_prered)} suite(s) fail before any mutation is "
              f"applied: {sorted(_prered)}.")
        print("    Every anchor naming one of them would report CAUGHT "
              "regardless of what it mutated. Fix the suite (or the sweep's "
              "copy) before trusting any verdict below.")
        sys.exit(1)
    tally = {}
    for i, mut in enumerate(MUTATIONS):
        if only and str(i) not in only:
            continue
        r = run(i, *mut)
        tally[r] = tally.get(r, 0) + 1
    print("\n", tally)
    # SKIP IS NOT A PASS, and neither is a crashed suite -- this file's header
    # says so twice and then exited 0 anyway, so a sweep that covered 58 of 65
    # guarantees looked exactly like one that covered all of them. Six anchors
    # had rotted silently before anyone re-read the tally by hand.
    _bad = {k: v for k, v in tally.items() if k != "CAUGHT"}
    if _bad:
        print(f"\n[!] {sum(_bad.values())} mutation(s) did not produce a "
              f"verdict: {_bad}.")
        print("    SKIP means the anchor no longer matches, so that guarantee "
              "was NOT swept -- re-anchor it against the current source. "
              "SURVIVED means nothing noticed. NO-RESULT means the suite "
              "crashed, which proves nothing about its checks.")
        sys.exit(1)
