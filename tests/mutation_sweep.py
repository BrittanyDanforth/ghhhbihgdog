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
  # Re-anchored: the held breakdown gained a third kind (a stopped peel
  # chain's undistributed remainder), so the condition names three counts.
  "        elif _relayed and not (_held_entry or _held_change or _held_remainder):",
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
  "    if JOB_TIMEOUT_EXPLICIT:\n        return JOB_TIMEOUT_S",
  "    if False:\n        return JOB_TIMEOUT_S",
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
  '    return all(0 <= int(p) <= 255 for p in v.split("."))',
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
  "        if not args.dry_run:\n"
  "            _sleep(_rng.randint(NO_JOB_DWELL_LO_S, NO_JOB_DWELL_HI_S))",
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


if __name__ == "__main__":
    only = set(sys.argv[1:])
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
