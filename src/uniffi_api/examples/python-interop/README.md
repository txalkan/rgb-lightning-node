# Python SDK-Only Node-to-Node Example

This example runs a full local regtest flow from Python using **UniFFI SDK methods only** (no HTTP route calls):

1. Create two `SdkNode` instances in-process
2. `init` + `unlock` both
3. Fund node A on regtest
4. `connectpeer` + `openchannel`
5. Create invoice on node B via `ln_invoice`
6. Pay from node A via `sendpayment`
7. Verify final invoice status via `invoice_status`

## Prerequisites

From repo root:

```sh
cd /home/roman-boiko/projects/utexo/rgb-lightning-node
```

Build library and generate Python bindings:

```sh
cargo build --release --features uniffi --lib
./scripts/ci/uniffi_generate_python.sh
```

Set env:

```sh
export PYTHONPATH="$PWD/target/uniffi/python:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="$PWD/target/release:${LD_LIBRARY_PATH:-}"
```

Start regtest dependencies:

```sh
./regtest.sh start
```

## Run

```sh
python3 src/uniffi_api/examples/python-interop/manual_py_full_n2n.py
```

Optional env overrides:

```sh
RESET_DATA=1 \
NODE_A_STORAGE="$PWD/sdkdata_py/node_a" \
NODE_B_STORAGE="$PWD/sdkdata_py/node_b" \
NODE_A_PEER_PORT=9735 \
NODE_B_PEER_PORT=9736 \
python3 src/uniffi_api/examples/python-interop/manual_py_full_n2n.py
```

Notes:

- `RESET_DATA=1` removes storage dirs before run.
- Script uses `./regtest.sh sendtoaddress` and `./regtest.sh mine` for funding/confirmations.
- Script shuts down both SDK nodes on exit.

## Cleanup

```sh
./regtest.sh stop
```
