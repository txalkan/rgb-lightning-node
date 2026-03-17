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

# These ports are part of node config even when HTTP API is not used.
NODE_A_DAEMON_PORT = int(os.getenv("NODE_A_DAEMON_PORT", "3101"))
NODE_B_DAEMON_PORT = int(os.getenv("NODE_B_DAEMON_PORT", "3102"))

NODE_A_PEER_PORT = int(os.getenv("NODE_A_PEER_PORT", "9735"))
NODE_B_PEER_PORT = int(os.getenv("NODE_B_PEER_PORT", "9736"))

NODE_A_PASSWORD = os.getenv("NODE_A_PASSWORD", "nodeApass")
NODE_B_PASSWORD = os.getenv("NODE_B_PASSWORD", "nodeBpass")

OPEN_CHANNEL_CAPACITY_SAT = int(os.getenv("OPEN_CHANNEL_CAPACITY_SAT", "500000"))
OPEN_CHANNEL_PUSH_MSAT = int(os.getenv("OPEN_CHANNEL_PUSH_MSAT", "0"))
PAYMENT_MSAT = int(os.getenv("PAYMENT_MSAT", "1000000"))

RESET_DATA = os.getenv("RESET_DATA", "0") == "1"


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
    )
    return rln.SdkNode.create(req)


def init_if_needed(node: rln.SdkNode, password: str, name: str):
    try:
        mnemonic = node.init(password, None)
        print(f"{name}: initialized")
        print(f"{name}: mnemonic[0..20]={mnemonic[:20]}...")
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


def ensure_funded(node: rln.SdkNode, min_spendable_sat: int):
    bal = node.btc_balance(False)
    spendable = bal.vanilla.spendable
    print(f"node A spendable sats: {spendable}")
    if spendable >= min_spendable_sat:
        return

    addr = node.address().address
    print(f"Funding node A address {addr} with 0.02 BTC on regtest")
    run_regtest("sendtoaddress", addr, "0.02")
    run_regtest("mine", "6")
    node.sync()

    bal2 = node.btc_balance(False)
    spendable2 = bal2.vanilla.spendable
    print(f"node A spendable sats after funding: {spendable2}")
    if spendable2 < min_spendable_sat:
        raise RuntimeError(
            f"node A spendable balance still too low: {spendable2} < {min_spendable_sat}"
        )


def has_usable_channel(node: rln.SdkNode) -> bool:
    return any(ch.is_usable for ch in node.list_channels())


def wait_for_usable_channel(node_a: rln.SdkNode, node_b: rln.SdkNode, timeout_sec: int = 120):
    deadline = time.time() + timeout_sec
    last = []
    while time.time() < deadline:
        node_a.sync()
        node_b.sync()
        chans = node_a.list_channels()
        last = [(str(c.channel_id), c.status.name, c.is_usable) for c in chans]
        if any(c.is_usable for c in chans):
            return
        print("waiting for usable channel...")
        time.sleep(2)
    raise RuntimeError(f"No usable channel after {timeout_sec}s. last={last}")


def wait_payment_final(node_b: rln.SdkNode, invoice: str, timeout_sec: int = 60):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        node_b.sync()
        status = node_b.invoice_status(invoice)
        last = status
        if status in (rln.InvoiceStatus.SUCCEEDED, rln.InvoiceStatus.FAILED, rln.InvoiceStatus.EXPIRED):
            return status
        time.sleep(1)
    raise RuntimeError(f"Invoice did not finalize after {timeout_sec}s, last={last}")


def main():
    print("Pure SDK N2N flow (no HTTP calls)")
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

        ensure_funded(node_a, OPEN_CHANNEL_CAPACITY_SAT + 50_000)

        info_a = node_a.node_info()
        info_b = node_b.node_info()
        print("node A pubkey:", info_a.pubkey)
        print("node B pubkey:", info_b.pubkey)

        peer_uri = f"{info_b.pubkey}@127.0.0.1:{NODE_B_PEER_PORT}"
        try:
            node_a.connectpeer(peer_uri)
            print("connectpeer: ok")
        except rln.RlnError.Conflict:
            print("connectpeer: already connected")

        if has_usable_channel(node_a):
            print("usable channel already exists, skipping openchannel")
        else:
            open_req = rln.SdkOpenChannelRequest(
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
            )
            open_resp = node_a.openchannel(open_req)
            print("openchannel temporary_channel_id:", open_resp.temporary_channel_id)

            print("Mining 6 blocks for channel confirmations...")
            run_regtest("mine", "6")

            wait_for_usable_channel(node_a, node_b)
            print("Channel is usable")

        print("node A channels:", len(node_a.list_channels()))
        print("node B channels:", len(node_b.list_channels()))

        inv_req = rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=3600,
            asset_id=None,
            asset_amount=None,
        )
        invoice = node_b.ln_invoice(inv_req).invoice
        print("invoice:", invoice)

        pay_req = rln.SdkSendPaymentRequest(
            invoice=invoice,
            amt_msat=PAYMENT_MSAT,
            asset_id=None,
            asset_amount=None,
        )
        pay_resp = node_a.sendpayment(pay_req)
        print("sendpayment status:", pay_resp.status.name)
        print("sendpayment payment_id:", pay_resp.payment_id)

        final_status = wait_payment_final(node_b, invoice)
        print("invoice final status on node B:", final_status.name)

        if final_status != rln.InvoiceStatus.SUCCEEDED:
            raise RuntimeError(f"Payment did not succeed (status={final_status})")

        print("SUCCESS: SDK-only node-to-node payment completed")
    finally:
        node_a.shutdown()
        node_b.shutdown()


if __name__ == "__main__":
    main()
