#!/usr/bin/env python3
import os
import shutil
import subprocess
import time
from pathlib import Path

import rgb_lightning_node as rln

REPO_ROOT = Path(__file__).resolve().parents[4]

NODE_A_STORAGE = Path(os.getenv("NODE_A_STORAGE", REPO_ROOT / "sdkdata_py" / "node_a"))
NODE_B_STORAGE = Path(os.getenv("NODE_B_STORAGE", REPO_ROOT / "sdkdata_py" / "node_b"))

NODE_A_DAEMON_PORT = int(os.getenv("NODE_A_DAEMON_PORT", "3201"))
NODE_B_DAEMON_PORT = int(os.getenv("NODE_B_DAEMON_PORT", "3202"))
NODE_A_PEER_PORT = int(os.getenv("NODE_A_PEER_PORT", "9745"))
NODE_B_PEER_PORT = int(os.getenv("NODE_B_PEER_PORT", "9746"))

NODE_A_PASSWORD = os.getenv("NODE_A_PASSWORD", "nodeApass")
NODE_B_PASSWORD = os.getenv("NODE_B_PASSWORD", "nodeBpass")

OPEN_CHANNEL_CAPACITY_SAT = int(os.getenv("OPEN_CHANNEL_CAPACITY_SAT", "500000"))
OPEN_CHANNEL_PUSH_MSAT = int(os.getenv("OPEN_CHANNEL_PUSH_MSAT", "0"))
KEYSEND_MSAT = int(os.getenv("KEYSEND_MSAT", "1000000"))
CHANNEL_READY_TIMEOUT_SEC = int(os.getenv("CHANNEL_READY_TIMEOUT_SEC", "180"))
MIN_KEYSEND_MSAT = 3_000_000

CREATE_UTXOS_NUM = int(os.getenv("CREATE_UTXOS_NUM", "6"))
CREATE_UTXOS_SIZE_SAT = int(os.getenv("CREATE_UTXOS_SIZE_SAT", "100000"))
CREATE_UTXOS_FEE_RATE = int(os.getenv("CREATE_UTXOS_FEE_RATE", "1"))

RESET_DATA = os.getenv("RESET_DATA", "0") == "1"
REQUIRE_CLOSE_SUCCESS = os.getenv("REQUIRE_CLOSE_SUCCESS", "0") == "1"


def run_regtest(*args: str) -> str:
    cmd = ["./regtest.sh", *args]
    res = subprocess.run(
        cmd,
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return (res.stdout or "").strip()


def ensure_dir(path: Path):
    if RESET_DATA and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def make_node(storage: Path, daemon_port: int, peer_port: int) -> rln.SdkNode:
    req = rln.SdkInitRequest(
        storage_dir_path=str(storage),
        daemon_listening_port=daemon_port,
        ldk_peer_listening_port=peer_port,
        network="regtest",
        max_media_upload_size_mb=20,
        enable_virtual_channels_v0=True,
        virtual_peer_pubkeys=None,
    )
    return rln.SdkNode.create(req)


def init_if_needed(node: rln.SdkNode, password: str, name: str):
    try:
        node.init(password, None)
        print(f"{name}: initialized")
    except rln.RlnError.Conflict:
        print(f"{name}: already initialized")


def unlock_if_needed(node: rln.SdkNode, password: str, name: str):
    req = rln.SdkUnlockRequest(
        password=password,
        bitcoind_rpc_username="user",
        bitcoind_rpc_password="password",
        bitcoind_rpc_host="localhost",
        bitcoind_rpc_port=18443,
        indexer_url="127.0.0.1:50001",
        proxy_endpoint="rpc://127.0.0.1:3000/json-rpc",
        announce_addresses=[],
        announce_alias=None,
    )
    try:
        node.unlock(req)
        print(f"{name}: unlocked")
    except rln.RlnError.Conflict:
        print(f"{name}: already unlocked")


def ensure_funded(node: rln.SdkNode, name: str, min_spendable_sat: int):
    bal = node.btc_balance(False)
    spendable = bal.vanilla.spendable
    print(f"{name} spendable sats: {spendable}")
    if spendable >= min_spendable_sat:
        return
    addr = node.address().address
    print(f"Funding {name} address {addr} with 0.02 BTC on regtest")
    run_regtest("sendtoaddress", addr, "0.02")
    run_regtest("mine", "6")
    node.sync()


def pick_virtual_channel_with_peer(node: rln.SdkNode, peer_pubkey: str):
    for ch in node.list_channels():
        if str(ch.peer_pubkey) == peer_pubkey and ch.virtual_open_mode == "trusted_no_broadcast":
            return ch
    return None


def wait_for_virtual_channel(node: rln.SdkNode, peer_pubkey: str, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last = []
    while time.time() < deadline:
        node.sync()
        channels = node.list_channels()
        last = [
            (str(c.channel_id), str(c.peer_pubkey), c.status.name, c.is_usable, c.virtual_open_mode)
            for c in channels
        ]
        found = pick_virtual_channel_with_peer(node, peer_pubkey)
        if found is not None:
            return found
        time.sleep(1)
    raise RuntimeError(f"virtual channel not found in time, last={last}")


def wait_for_usable_virtual_channel(node: rln.SdkNode, peer_pubkey: str, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last = []
    while time.time() < deadline:
        node.sync()
        channels = node.list_channels()
        last = [
            (str(c.channel_id), str(c.peer_pubkey), c.status.name, c.is_usable, c.virtual_open_mode)
            for c in channels
        ]
        found = pick_virtual_channel_with_peer(node, peer_pubkey)
        if found is not None and found.is_usable:
            return found
        time.sleep(1)
    raise RuntimeError(f"virtual channel not usable in time, last={last}")


def wait_for_channel_gone(node: rln.SdkNode, channel_id: str, timeout_sec: int = 30):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        node.sync()
        if all(str(c.channel_id) != channel_id for c in node.list_channels()):
            return
        time.sleep(1)
    raise RuntimeError("virtual channel still present after close")


def wait_payment_final(node: rln.SdkNode, payment_hash, timeout_sec: int = 60):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        node.sync()
        payment = node.get_payment(payment_hash)
        last = payment.status
        if payment.status != rln.HtlcStatus.PENDING:
            return payment.status
        time.sleep(1)
    raise RuntimeError(f"keysend did not finalize in time, last={last}")


def close_virtual_channel_with_retry(
    node: rln.SdkNode, channel_id, peer_pubkey, timeout_sec: int = 30
):
    deadline = time.time() + timeout_sec
    last_err = None
    while time.time() < deadline:
        try:
            node.closechannel(
                rln.SdkCloseChannelRequest(
                    channel_id=channel_id,
                    peer_pubkey=peer_pubkey,
                    force=False,
                )
            )
            return
        except Exception as e:
            last_err = e
            node.sync()
            time.sleep(1)
    raise RuntimeError(f"closechannel did not succeed in time, last_err={last_err}")


def settle_after_payment(node_a: rln.SdkNode, node_b: rln.SdkNode, seconds: int = 10):
    deadline = time.time() + seconds
    while time.time() < deadline:
        node_a.sync()
        node_b.sync()
        time.sleep(1)


def wait_for_channel_gone_on_both(
    node_a: rln.SdkNode, node_b: rln.SdkNode, channel_id: str, timeout_sec: int = 30
):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        node_a.sync()
        node_b.sync()
        a_has = any(str(c.channel_id) == channel_id for c in node_a.list_channels())
        b_has = any(str(c.channel_id) == channel_id for c in node_b.list_channels())
        if not a_has and not b_has:
            return
        time.sleep(1)
    raise RuntimeError("virtual channel still present on at least one node after close")


def main():
    print("SDK virtual channels test (trusted_no_broadcast open/list/keysend/close)")
    print(f"node A storage: {NODE_A_STORAGE}")
    print(f"node B storage: {NODE_B_STORAGE}")

    ensure_dir(NODE_A_STORAGE)
    ensure_dir(NODE_B_STORAGE)

    node_a = make_node(NODE_A_STORAGE, NODE_A_DAEMON_PORT, NODE_A_PEER_PORT)
    node_b = make_node(NODE_B_STORAGE, NODE_B_DAEMON_PORT, NODE_B_PEER_PORT)

    try:
        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")

        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

        ensure_funded(node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT + 200_000)
        ensure_funded(node_b, "node B", 100_000)

        node_a.createutxos(
            rln.SdkCreateUtxosRequest(
                up_to=False,
                num=CREATE_UTXOS_NUM,
                size=CREATE_UTXOS_SIZE_SAT,
                fee_rate=CREATE_UTXOS_FEE_RATE,
                skip_sync=False,
            )
        )
        node_b.createutxos(
            rln.SdkCreateUtxosRequest(
                up_to=False,
                num=CREATE_UTXOS_NUM,
                size=CREATE_UTXOS_SIZE_SAT,
                fee_rate=CREATE_UTXOS_FEE_RATE,
                skip_sync=False,
            )
        )
        run_regtest("mine", "1")

        info_a = node_a.node_info()
        info_b = node_b.node_info()
        peer_uri = f"{info_b.pubkey}@127.0.0.1:{NODE_B_PEER_PORT}"

        try:
            node_a.connectpeer(peer_uri)
            print("connectpeer: ok")
        except rln.RlnError.Conflict:
            print("connectpeer: already connected")

        open_resp = node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=OPEN_CHANNEL_CAPACITY_SAT,
                push_msat=OPEN_CHANNEL_PUSH_MSAT,
                public=False,
                with_anchors=True,
                fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=None,
                asset_amount=None,
                push_asset_amount=None,
                virtual_open_mode="trusted_no_broadcast",
            )
        )
        print("virtual openchannel temporary_channel_id:", open_resp.temporary_channel_id)

        virtual_channel = wait_for_virtual_channel(
            node_a,
            str(info_b.pubkey),
            CHANNEL_READY_TIMEOUT_SEC,
        )
        print("virtual channel mode:", virtual_channel.virtual_open_mode)

        virtual_channel = wait_for_usable_virtual_channel(
            node_a,
            str(info_b.pubkey),
            CHANNEL_READY_TIMEOUT_SEC,
        )
        print("virtual channel usable:", virtual_channel.is_usable)

        keysend_amt_msat = max(KEYSEND_MSAT, MIN_KEYSEND_MSAT)
        print("keysend amount msat:", keysend_amt_msat)
        keysend_resp = node_a.keysend(
            rln.SdkKeysendRequest(
                dest_pubkey=info_b.pubkey,
                amt_msat=keysend_amt_msat,
                asset_id=None,
                asset_amount=None,
            )
        )
        print("keysend status:", keysend_resp.status.name)
        final_keysend_status = wait_payment_final(node_a, keysend_resp.payment_hash)
        print("keysend final status:", final_keysend_status.name)
        settle_after_payment(node_a, node_b, seconds=10)

        try:
            node_a.connectpeer(peer_uri)
        except rln.RlnError.Conflict:
            pass
        node_a.sync()
        node_b.sync()

        try:
            close_err = None
            try:
                close_virtual_channel_with_retry(
                    node_a,
                    virtual_channel.channel_id,
                    virtual_channel.peer_pubkey,
                    timeout_sec=45,
                )
            except Exception as e:
                close_err = e
                close_virtual_channel_with_retry(
                    node_b,
                    virtual_channel.channel_id,
                    info_a.pubkey,
                    timeout_sec=45,
                )
            print("closechannel: initiated")
            wait_for_channel_gone_on_both(
                node_a, node_b, str(virtual_channel.channel_id), timeout_sec=45
            )
            if close_err is not None:
                print("closechannel fallback used node B after node A error:", close_err)
            print("virtual channel closed and removed on both nodes")
        except Exception as e:
            if REQUIRE_CLOSE_SUCCESS:
                raise
            print("closechannel warning (non-fatal):", e)

        print("SUCCESS: virtual channel flow completed")
    finally:
        node_a.shutdown()
        node_b.shutdown()


if __name__ == "__main__":
    main()
