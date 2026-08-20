"""A throwaway Monero chain running CURRENT consensus, for the real-binary suites.

WHY THIS EXISTS, and it is not a convenience wrapper.

Every suite here used to start `monerod --testnet --offline`. A fresh chain
there begins at height 0, and testnet's next hard fork is at height 624634, so
a suite that mines a few hundred blocks is running under hard fork **v1** --
the original 2014 rules. That is PRE-RingCT:

  * amounts are PLAINTEXT and outputs are denominated into powers of ten, so a
    two-destination transfer lands as 7-12 on-chain outputs instead of 3,
  * ring size is 1 (mixin 0 is legal), not the mandatory 16,
  * fees are the old per-KB schedule, and the denomination bloat inflates them
    enormously.

None of that is how Monero works today, and measurements taken there do not
transfer. This is not hypothetical: a peel chain measured on such a chain
appeared to need ~82x the daemon's fee estimate as headroom per hop, and that
number was written into GhostSpiral as a constant. Re-measured under current
rules the real requirement is ~1.25x. The constant had been "fixed" twice
before anyone questioned the chain it was measured on.

`monerod --regtest` is hard fork v16 from height 1 -- RingCT, ring 16, current
fee rules -- and start() ASSERTS that rather than trusting the flag.

Two things about regtest that cost an afternoon each:

  * FAKECHAIN falls through to the MAINNET branch of get_config(), so its
    addresses carry mainnet prefixes. The wallet must run with NO network flag;
    `--testnet` yields "Failed to parse wallet address" from generateblocks.
  * A mainnet-mode wallet knows mainnet's fork heights and refuses a chain with
    v16 at height 1 ("Unexpected hard fork version"), so it needs
    --allow-mismatched-daemon-version.

Blocks come from `generateblocks`, which is instant and exact. The old suites
used start_mining and polled for a target height, which overshoots by however
many blocks land before the stop request is seen -- enough to make a
locked-output test inconclusive.
"""
import json
import os
import subprocess
import time

import requests


class MoneroLab:
    """monerod --regtest + monero-wallet-rpc, both on loopback, both disposable."""

    def __init__(self, base, daemon_port, wallet_port):
        self.base = base
        self.dp = int(daemon_port)
        self.wp = int(wallet_port)
        self.DR = f"http://127.0.0.1:{self.dp}"
        self.WR = f"http://127.0.0.1:{self.wp}/json_rpc"
        self.procs = []

    # -- RPC ---------------------------------------------------------------
    def dj(self, method, params=None):
        """Daemon json_rpc."""
        body = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            body["params"] = params
        return requests.post(self.DR + "/json_rpc", json=body, timeout=180).json()

    def draw(self, path, body=None):
        """Daemon non-json_rpc endpoint, e.g. /get_transactions."""
        return requests.post(self.DR + path, json=body or {}, timeout=180).json()

    def wj(self, method, params=None, timeout=600, t=None):
        """Wallet json_rpc.

        `t` is accepted as an alias for `timeout` because the suites this
        replaced defined `wj(m, p=None, t=120)`. Keeping the alias is what
        lets their call sites -- and therefore their assertions -- stay
        untouched while the chain underneath them changes.
        """
        if t is not None:
            timeout = t
        body = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            body["params"] = params
        return requests.post(self.WR, json=body, timeout=timeout).json()

    def height(self):
        return self.dj("get_info")["result"]["height"]

    def fee_estimate(self, priority=1):
        """The daemon's per-TX fee estimate in ATOMIC units, for `priority`.

        Mirrors GhostSpiral.fetch_fee_from_daemon: prefer the per-priority
        fees[] array the modern daemon returns, and scale by the same 2000
        bytes it uses.
        """
        r = self.dj("get_fee_estimate")["result"]
        fees = r.get("fees") or []
        base = int(fees[priority - 1]) if fees else int(r["fee"])
        return base * 2000

    def gen(self, address, n):
        """Mine exactly n blocks to `address`, and PROVE the chain grew.

        MALFORMED SUCCESS LIVES HERE. On a node that is not synchronized --
        which is any regtest node started without --offline and without a peer
        -- generateblocks answers

            {"height": 0, "status": "BUSY", "untrusted": false}

        with NO "error" key. Checking only for `error` therefore reported
        success while producing zero blocks, and every downstream failure
        ("not enough money", "no unlocked balance") pointed somewhere else
        entirely. The absence of an error is not a postcondition.

        So: check the documented status field, and then independently observe
        that the height actually moved.
        """
        left = int(n)
        want = self.height() + left
        while left > 0:
            step = min(left, 40)
            before = self.height()
            r = self.dj("generateblocks", {"amount_of_blocks": step,
                                           "wallet_address": address,
                                           "starting_nonce": 0})
            if "error" in r:
                raise RuntimeError(f"generateblocks failed: {r['error']}")
            status = (r.get("result") or {}).get("status")
            if status != "OK":
                raise RuntimeError(
                    f"generateblocks answered status={status!r} instead of OK "
                    f"(no error key, so this looks like success). The node is "
                    f"most likely not synchronized: a regtest node started "
                    f"without --offline and without a peer never reports "
                    f"synchronized, and refuses to generate.")
            after = self.height()
            if after <= before:
                raise RuntimeError(
                    f"generateblocks reported OK but the height did not move "
                    f"({before} -> {after}).")
            left -= step
        got = self.height()
        if got < want:
            raise RuntimeError(f"asked for {n} blocks, chain reached {got} "
                               f"instead of {want}")
        self.wj("refresh")

    def mine(self, address, target_height):
        """Mine until the chain reaches `target_height`. Drop-in for the
        `mine(addr, target)` helper the older suites define.

        They used start_mining and polled: that overshoots by however many
        blocks land before the stop request is seen, which is enough to make a
        locked-output test inconclusive. It also does not work here at all --
        current consensus mines with RandomX, and this environment cannot
        allocate its cache. generateblocks is exact and instant.
        """
        have = self.height()
        if target_height > have:
            self.gen(address, target_height - have)
        else:
            self.wj("refresh")

    def bind(self, namespace):
        """Point a suite's dj/draw/wj/mine helpers at this lab.

        The suites were written around module-level helper functions and a
        hand-rolled launch block. Rebinding them is what lets the SUITE's
        assertions stay exactly as they were while the chain underneath them
        changes from hard fork v1 to current consensus -- which is the whole
        point: if an assertion only held because of pre-RingCT rules, it must
        now fail rather than be quietly rewritten.
        """
        namespace["dj"] = self.dj
        namespace["draw"] = self.draw
        namespace["wj"] = self.wj
        namespace["mine"] = self.mine
        return self

    def tx_shapes(self, hashes):
        """(n_in, n_out, extra_len, ring_sizes, fee) for each hash, as an
        analyst reading the chain would see it -- no wallet involved."""
        import json as _json
        if not hashes:
            return []
        det = self.draw("/get_transactions",
                        {"txs_hashes": list(hashes), "decode_as_json": True})
        out = []
        for t in det.get("txs", []):
            aj = _json.loads(t.get("as_json", "{}") or "{}")
            rct = aj.get("rct_signatures") or {}
            out.append({
                "hash": t.get("tx_hash"),
                "n_in": len(aj.get("vin", [])),
                "n_out": len(aj.get("vout", [])),
                "extra_len": len(aj.get("extra", [])),
                "ring_sizes": [len(v.get("key", {}).get("key_offsets", []))
                               for v in aj.get("vin", [])],
                "fee": int(rct.get("txnFee", 0) or 0),
            })
        return out

    # -- lifecycle ---------------------------------------------------------
    def _daemon_argv(self, datadir, rpc_port, p2p_port, offline, peer_port=None):
        argv = ["monerod", "--regtest", "--no-zmq"]
        if offline:
            argv.append("--offline")
        argv += ["--data-dir", datadir,
                 "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(rpc_port),
                 "--p2p-bind-port", str(p2p_port), "--no-igd", "--hide-my-port",
                 "--fixed-difficulty", "1", "--non-interactive",
                 "--log-file", os.path.join(self.base, f"d{rpc_port}.log"),
                 "--log-level", "0"]
        if peer_port:
            argv += ["--add-exclusive-node", f"127.0.0.1:{peer_port}"]
        return argv

    def start(self, wallet=True, offline=True):
        """offline=False starts a SECOND daemon and peers the two.

        A regtest node with no peers never reports `synchronized`, and an
        unsynchronized node answers generateblocks with status BUSY and no
        error key -- so a lab that merely drops --offline silently produces no
        blocks. Two nodes peered to each other reach `synchronized` while
        still reaching nothing outside this host.

        offline=True is right for suites that only build and inspect
        transactions. offline=False is required to drive the shipped pipeline,
        whose preflight refuses an offline daemon on the grounds that "every
        broadcast would silently go nowhere" -- a correct guard that a lab
        must satisfy rather than bypass.
        """
        os.makedirs(os.path.join(self.base, "n"), exist_ok=True)
        if not offline:
            peer_dir = os.path.join(self.base, "peer")
            os.makedirs(peer_dir, exist_ok=True)
            self.procs.append(subprocess.Popen(
                self._daemon_argv(peer_dir, self.dp - 20, self.dp - 21, False,
                                  peer_port=self.dp - 1),
                stdout=open(os.path.join(self.base, "peer.out"), "w"),
                stderr=subprocess.STDOUT))
        self.procs.append(subprocess.Popen(
            self._daemon_argv(os.path.join(self.base, "n"), self.dp,
                              self.dp - 1, offline,
                              peer_port=None if offline else self.dp - 21),
            stdout=open(os.path.join(self.base, "d.out"), "w"),
            stderr=subprocess.STDOUT))
        for _ in range(60):
            time.sleep(1)
            if self.procs[-1].poll() is not None:
                raise RuntimeError(
                    f"monerod exited immediately (code {self.procs[-1].returncode}). "
                    f"See {os.path.join(self.base, 'd.out')}.")
            try:
                if self.dj("get_info").get("result", {}).get("height") is not None:
                    break
            except Exception:                                # noqa: BLE001
                pass
        else:
            raise RuntimeError("monerod did not come up")

        # IS THIS OUR DAEMON? Waiting for "something answers on the port" is
        # not the same question. A leftover daemon from an earlier run holds
        # the port, answers happily, and the suite then tests against a chain
        # it did not create -- which surfaced as
        # "Daemon response did not include the requested real output" from a
        # wallet whose outputs belonged to a different chain, an error that
        # says nothing about ports. A freshly started regtest node is at
        # height 1; anything else is not ours.
        h = self.height()
        if h > 1:
            raise RuntimeError(
                f"port {self.dp} is already serving a chain at height {h}. A "
                f"daemon from an earlier run is still alive, and this suite "
                f"would have tested against ITS chain. Kill it and re-run; do "
                f"not run two real-binary suites on the same ports at once.")

        # ASSERT the consensus rules, do not assume them. The whole point of
        # this class is that the chain is not the one --testnet gives you, and
        # a silent fallback to v1 would make every measurement wrong while
        # every test still passed.
        hf = self.dj("hard_fork_info").get("result", {})
        if not hf.get("enabled") or int(hf.get("version", 0)) < 15:
            raise RuntimeError(
                f"regtest is not running current consensus: {hf}. Expected an "
                f"enabled hard fork >= 15 (RingCT, ring 16). Without it the "
                f"chain is pre-RingCT and no fee, output-count or ring "
                f"measurement taken on it means anything.")
        if not offline:
            # An unsynchronized node answers generateblocks BUSY with no error
            # key, so wait for the peering to settle rather than discovering it
            # three phases later as "not enough money".
            for _ in range(60):
                if self.dj("get_info").get("result", {}).get("synchronized"):
                    break
                time.sleep(1)
            else:
                raise RuntimeError(
                    "the regtest node never reported synchronized even with a "
                    "peer; generateblocks would answer BUSY and produce "
                    "nothing. See " + os.path.join(self.base, "d.out"))

        if not wallet:
            return self

        self.procs.append(subprocess.Popen(
            # NO network flag: fakechain uses mainnet address prefixes.
            # --allow-mismatched-daemon-version: a mainnet-mode wallet knows
            # mainnet's fork heights and otherwise refuses v16 at height 1.
            ["monero-wallet-rpc",
             "--daemon-address", f"127.0.0.1:{self.dp}", "--trusted-daemon",
             "--wallet-dir", os.path.join(self.base, "w"),
             "--rpc-bind-port", str(self.wp), "--rpc-bind-ip", "127.0.0.1",
             "--disable-rpc-login", "--allow-mismatched-daemon-version",
             "--log-file", os.path.join(self.base, "w.log"), "--log-level", "0"],
            stdout=open(os.path.join(self.base, "w.out"), "w"),
            stderr=subprocess.STDOUT))
        for _ in range(60):
            time.sleep(1)
            try:
                if "result" in self.wj("get_version"):
                    return self
            except Exception:                                # noqa: BLE001
                pass
        raise RuntimeError("monero-wallet-rpc did not come up")

    @property
    def daemon_proc(self):
        """The monerod process, for suites that deliberately kill it.

        Failure injection needs a handle, not just an RPC url -- a suite that
        can only ask the daemon nicely cannot test what happens when it dies.
        """
        return self.procs[0] if self.procs else None

    def restore_cold_wallet(self, dest_file, address, spendkey, viewkey,
                            password=""):
        """Restore a spend-key wallet that has never opened against a daemon.

        wallet-cli refuses import_outputs (and sign_transfer when the unsigned
        set carries outputs to import) on any wallet file that has previously
        refreshed from a node -- 'Hot wallets cannot import outputs'. The
        lab's RPC wallet is always that kind of hot wallet. A genuine air-gap
        restore from keys, started with --offline and never connected, is
        what phase_sign's import is for.

        dest_file is the wallet path without a .keys suffix. Returns dest_file.
        """
        dest_file = os.path.abspath(dest_file)
        os.makedirs(os.path.dirname(dest_file) or ".", exist_ok=True)
        shm = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
        spec_dir = shm or os.path.dirname(dest_file)
        spec_path = os.path.join(spec_dir, os.path.basename(dest_file) + ".restore.json")
        spec = {
            "version": 1,
            "filename": dest_file,
            "password": password,
            "scan_from_height": 0,
            "address": address,
            "viewkey": viewkey,
            "spendkey": spendkey,
        }
        fd = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(spec).encode())
        finally:
            os.close(fd)
        try:
            r = subprocess.run(
                ["monero-wallet-cli", "--offline",
                 "--generate-from-json", spec_path,
                 "--subaddress-lookahead", "400:50"],
                capture_output=True, text=True, timeout=90,
                input="exit\n",
            )
        finally:
            try:
                os.remove(spec_path)
            except OSError:
                pass
        if not os.path.exists(dest_file):
            tail = (r.stderr or r.stdout or "")[-500:]
            raise RuntimeError(f"cold wallet restore did not write {dest_file}: {tail}")
        return dest_file

    def stop(self):
        for p in self.procs:
            try:
                p.terminate()
            except Exception:                                # noqa: BLE001
                pass
        time.sleep(1)
        for p in self.procs:
            try:
                p.kill()
            except Exception:                                # noqa: BLE001
                pass
        self.procs = []

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
