use bitcoin::secp256k1::PublicKey;
use lightning::io;
use lightning::ln::msgs::{DecodeError, Init, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::types::features::{InitFeatures, NodeFeatures};
use lightning::util::ser::{LengthLimitedRead, LengthReadable, WithoutLength, Writeable, Writer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use tracing::warn;

use crate::utils::{hex_str, validate_and_parse_payment_hash};

pub(crate) const ASYNC_ORDER_MESSAGE_TYPE_ID: u16 = 37915;
const ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT: i64 = 1004;
const ASYNC_ERROR_DUPLICATE_HASH_CONFLICT: i64 = 1005;
const ASYNC_ERROR_INVALID_HASH_BATCH: i64 = 1003;
const ASYNC_ERROR_UNSUPPORTED_PROTOCOL_VERSION: i64 = 1000;
const DEFAULT_REFILL_BATCH_SIZE: &str = "200";
const JSONRPC_INVALID_PARAMS: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AsyncOrderMessage {
    pub(crate) payload: String,
}

impl Type for AsyncOrderMessage {
    fn type_id(&self) -> u16 {
        ASYNC_ORDER_MESSAGE_TYPE_ID
    }
}

impl Writeable for AsyncOrderMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
        WithoutLength(&self.payload).write(w)
    }
}

impl LengthReadable for AsyncOrderMessage {
    fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
        let payload_without_length: WithoutLength<String> =
            LengthReadable::read_from_fixed_length_buffer(r)?;
        Ok(Self {
            payload: payload_without_length.0,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AsyncOrderEnvelope {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncOrderNewHashWire {
    pub(crate) hash_index: String,
    pub(crate) payment_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncOrderNewParamsWire {
    pub(crate) protocol_version: String,
    pub(crate) hashes: Vec<AsyncOrderNewHashWire>,
}

#[derive(Clone, Debug, Serialize)]
struct AsyncOrderNewResultWire {
    protocol_version: String,
    order_id: String,
    status: String,
    accepted_through_index: String,
    next_index_expected: String,
    unused_hashes: String,
    refill_batch_size: String,
}

#[derive(Clone, Debug, Serialize)]
struct JsonRpcErrorWire {
    code: i64,
    message: String,
}

#[derive(Debug)]
pub(crate) struct AsyncOrderMessageHandler {
    state: Mutex<AsyncOrderState>,
}

#[derive(Debug)]
struct AsyncOrderState {
    next_order_id: u64,
    peers: HashMap<PublicKey, PeerOrderState>,
    pending: Vec<(PublicKey, AsyncOrderMessage)>,
}

#[derive(Debug, Default)]
struct PeerOrderState {
    active_order: Option<AsyncOrderRecord>,
}

#[derive(Debug, Clone)]
struct AsyncOrderRecord {
    order_id: u64,
    hashes: BTreeMap<u64, String>,
}

impl Default for AsyncOrderState {
    fn default() -> Self {
        Self {
            next_order_id: 1,
            peers: HashMap::new(),
            pending: Vec::new(),
        }
    }
}

impl AsyncOrderMessageHandler {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(AsyncOrderState::default()),
        }
    }

    fn queue_jsonrpc_value(&self, peer: PublicKey, value: Value) {
        let mut state = self.state.lock().unwrap();
        state.pending.push((
            peer,
            AsyncOrderMessage {
                payload: value.to_string(),
            },
        ));
    }

    fn queue_jsonrpc_result(&self, peer: PublicKey, id: Value, result: AsyncOrderNewResultWire) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "result": result,
            }),
        );
    }

    fn queue_jsonrpc_error(&self, peer: PublicKey, id: Value, code: i64, message: &str) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "error": JsonRpcErrorWire {
                    code,
                    message: message.to_owned(),
                },
            }),
        );
    }

    fn queue_jsonrpc_parse_error(&self, peer: PublicKey) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": Value::Null,
                "error": JsonRpcErrorWire::parse_error(),
            }),
        );
    }

    fn apply_async_order_new(
        &self,
        sender_node_id: PublicKey,
        params: AsyncOrderNewParamsWire,
    ) -> Result<AsyncOrderNewResultWire, JsonRpcErrorWire> {
        if params.protocol_version != PROTOCOL_VERSION {
            return Err(JsonRpcErrorWire::unsupported_protocol_version());
        }
        if params.hashes.is_empty() {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let parsed_hashes = parse_hash_batch(params.hashes)?;

        let mut state = self.state.lock().unwrap();
        let needs_new_order = match state.peers.get(&sender_node_id) {
            Some(peer_state) => peer_state.active_order.is_none(),
            None => true,
        };
        if needs_new_order {
            let order_id = state.next_order_id;
            state.next_order_id = state
                .next_order_id
                .checked_add(1)
                .expect("order id counter to not overflow");
            state.peers.entry(sender_node_id).or_default().active_order =
                Some(AsyncOrderRecord::new(order_id));
        }

        let peer_state = state.peers.get_mut(&sender_node_id).unwrap();
        let order = peer_state.active_order.as_mut().unwrap();
        order.merge_hashes(&parsed_hashes)?;

        Ok(order.snapshot_result())
    }
}

impl Default for AsyncOrderMessageHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl CustomMessageReader for AsyncOrderMessageHandler {
    type CustomMessage = AsyncOrderMessage;

    fn read<RD: LengthLimitedRead>(
        &self,
        message_type: u16,
        buffer: &mut RD,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        if message_type != ASYNC_ORDER_MESSAGE_TYPE_ID {
            return Ok(None);
        }

        Ok(Some(AsyncOrderMessage::read_from_fixed_length_buffer(
            buffer,
        )?))
    }
}

impl CustomMessageHandler for AsyncOrderMessageHandler {
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        if msg.payload.as_bytes().contains(&0) {
            warn!(payload = %msg.payload, "async_order peer message contained a NUL byte");
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        }

        let envelope: AsyncOrderEnvelope = match serde_json::from_str(&msg.payload) {
            Ok(envelope) => envelope,
            Err(err) => {
                warn!(error = %err, payload = %msg.payload, "failed to decode async_order peer message");
                self.queue_jsonrpc_parse_error(sender_node_id);
                return Ok(());
            }
        };

        if envelope.jsonrpc != JSONRPC_VERSION {
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        }

        if envelope.result.is_some() || envelope.error.is_some() {
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        }

        let Some(method) = envelope.method else {
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        };

        let Some(id) = envelope.id else {
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        };

        if method == "async_order.new" {
            let params_value = match envelope.params {
                Some(params) => params,
                None => {
                    self.queue_jsonrpc_error(
                        sender_node_id,
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "missing params",
                    );
                    return Ok(());
                }
            };

            let params: AsyncOrderNewParamsWire = match serde_json::from_value(params_value) {
                Ok(params) => params,
                Err(err) => {
                    warn!(error = %err, "invalid async_order.new params from {sender_node_id}");
                    self.queue_jsonrpc_error(
                        sender_node_id,
                        id,
                        ASYNC_ERROR_INVALID_HASH_BATCH,
                        "invalid_hash_batch",
                    );
                    return Ok(());
                }
            };

            match self.apply_async_order_new(sender_node_id, params) {
                Ok(result) => self.queue_jsonrpc_result(sender_node_id, id, result),
                Err(err) => self.queue_jsonrpc_error(sender_node_id, id, err.code, &err.message),
            }
            return Ok(());
        }

        self.queue_jsonrpc_error(
            sender_node_id,
            id,
            JSONRPC_METHOD_NOT_FOUND,
            "method not found",
        );
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut state.pending)
    }

    fn peer_disconnected(&self, _their_node_id: PublicKey) {}

    fn peer_connected(
        &self,
        _their_node_id: PublicKey,
        _msg: &Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }
}

impl AsyncOrderRecord {
    fn new(order_id: u64) -> Self {
        Self {
            order_id,
            hashes: BTreeMap::new(),
        }
    }

    fn highest_hash_index(&self) -> u64 {
        self.hashes.keys().next_back().copied().unwrap_or(0)
    }

    fn next_hash_index(&self) -> u64 {
        self.highest_hash_index().saturating_add(1)
    }

    fn available_hashes(&self) -> u64 {
        self.hashes.len() as u64
    }

    fn merge_hashes(&mut self, hashes: &[(u64, String)]) -> Result<(), JsonRpcErrorWire> {
        if hashes.is_empty() {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let expected_start = self.next_hash_index();
        let mut saw_existing = false;
        let mut saw_missing = false;
        let mut seen_batch_hashes = HashSet::new();

        for (index, payment_hash) in hashes {
            if !seen_batch_hashes.insert(payment_hash.clone()) {
                return Err(JsonRpcErrorWire::duplicate_hash_conflict());
            }

            match self.hashes.get(index) {
                Some(existing) if existing == payment_hash => {
                    saw_existing = true;
                }
                Some(_) => {
                    return Err(JsonRpcErrorWire::duplicate_index_conflict());
                }
                None => {
                    saw_missing = true;
                }
            }

            if self.hashes.iter().any(|(existing_index, existing_hash)| {
                *existing_index != *index && existing_hash == payment_hash
            }) {
                return Err(JsonRpcErrorWire::duplicate_hash_conflict());
            }
        }

        if saw_existing && saw_missing {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        if saw_existing {
            return Ok(());
        }

        if hashes.first().map(|(index, _)| *index) != Some(expected_start) {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        for (index, payment_hash) in hashes {
            self.hashes.insert(*index, payment_hash.clone());
        }

        Ok(())
    }

    fn snapshot_result(&self) -> AsyncOrderNewResultWire {
        AsyncOrderNewResultWire {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            order_id: self.order_id.to_string(),
            status: "active".to_owned(),
            accepted_through_index: self.highest_hash_index().to_string(),
            next_index_expected: self.next_hash_index().to_string(),
            unused_hashes: self.available_hashes().to_string(),
            refill_batch_size: DEFAULT_REFILL_BATCH_SIZE.to_owned(),
        }
    }
}

impl JsonRpcErrorWire {
    fn parse_error() -> Self {
        Self {
            code: JSONRPC_PARSE_ERROR,
            message: "parse error".to_owned(),
        }
    }

    fn duplicate_index_conflict() -> Self {
        Self {
            code: ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT,
            message: "duplicate_index_conflict".to_owned(),
        }
    }

    fn duplicate_hash_conflict() -> Self {
        Self {
            code: ASYNC_ERROR_DUPLICATE_HASH_CONFLICT,
            message: "duplicate_hash_conflict".to_owned(),
        }
    }

    fn invalid_hash_batch() -> Self {
        Self {
            code: ASYNC_ERROR_INVALID_HASH_BATCH,
            message: "invalid_hash_batch".to_owned(),
        }
    }

    fn unsupported_protocol_version() -> Self {
        Self {
            code: ASYNC_ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            message: "unsupported_protocol_version".to_owned(),
        }
    }
}

fn parse_hash_batch(
    hashes: Vec<AsyncOrderNewHashWire>,
) -> Result<Vec<(u64, String)>, JsonRpcErrorWire> {
    let mut parsed = Vec::with_capacity(hashes.len());
    let mut previous_index: Option<u64> = None;

    for entry in hashes {
        let index = entry
            .hash_index
            .parse::<u64>()
            .map_err(|_| JsonRpcErrorWire::invalid_hash_batch())?;
        let payment_hash = validate_and_parse_payment_hash(&entry.payment_hash)
            .map_err(|_| JsonRpcErrorWire::invalid_hash_batch())?;

        if let Some(previous) = previous_index {
            if index != previous.saturating_add(1) {
                return Err(JsonRpcErrorWire::invalid_hash_batch());
            }
        }

        previous_index = Some(index);
        parsed.push((index, hex_str(&payment_hash.0)));
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::new_jsonrpc_request_id;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_peer_pubkey(tag: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = tag.max(1);
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret_key)
    }

    fn new_request_payload(id: &str, hashes: &[(u64, &str)]) -> String {
        let hashes = hashes
            .iter()
            .map(|(hash_index, payment_hash)| {
                json!({
                    "hash_index": hash_index.to_string(),
                    "payment_hash": payment_hash,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "method": "async_order.new",
            "params": {
                "protocol_version": PROTOCOL_VERSION,
                "hashes": hashes,
            },
        })
        .to_string()
    }

    fn read_single_response(handler: &AsyncOrderMessageHandler) -> Value {
        let pending = handler.get_and_clear_pending_msg();
        assert_eq!(pending.len(), 1);
        serde_json::from_str(&pending[0].1.payload).unwrap()
    }

    #[test]
    fn async_order_new_creates_order_and_returns_state() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(1);
        let request_id = new_jsonrpc_request_id();
        let request_payload = new_request_payload(
            &request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], request_id);
        assert_eq!(
            response_value["result"]["protocol_version"],
            PROTOCOL_VERSION
        );
        assert_eq!(response_value["result"]["order_id"], "1");
        assert_eq!(response_value["result"]["status"], "active");
        assert_eq!(response_value["result"]["accepted_through_index"], "2");
        assert_eq!(response_value["result"]["next_index_expected"], "3");
        assert_eq!(response_value["result"]["unused_hashes"], "2");
        assert_eq!(
            response_value["result"]["refill_batch_size"],
            DEFAULT_REFILL_BATCH_SIZE
        );
    }

    #[test]
    fn async_order_new_is_idempotent_for_identical_batch() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(2);
        let request_id = new_jsonrpc_request_id();
        let request_payload = new_request_payload(
            &request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload.clone(),
                },
                test_peer,
            )
            .unwrap();
        let first_response = read_single_response(&handler);
        assert_eq!(first_response["id"], request_id);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload,
                },
                test_peer,
            )
            .unwrap();
        let second_response = read_single_response(&handler);

        assert_eq!(first_response, second_response);
    }

    #[test]
    fn async_order_new_rejects_conflicting_index() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(3);
        let initial_request_id = new_jsonrpc_request_id();
        let initial_request_payload = new_request_payload(
            &initial_request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: initial_request_payload,
                },
                test_peer,
            )
            .unwrap();
        read_single_response(&handler);

        let conflicting_request_id = new_jsonrpc_request_id();
        let conflicting_request_payload = new_request_payload(
            &conflicting_request_id,
            &[(
                1,
                "accccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: conflicting_request_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["id"], conflicting_request_id);
        assert_eq!(
            response_value["error"]["code"],
            ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT
        );
        assert_eq!(
            response_value["error"]["message"],
            "duplicate_index_conflict"
        );
    }

    #[test]
    fn async_order_new_rejects_repeated_payment_hash() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(6);
        let initial_request_id = new_jsonrpc_request_id();

        let initial_request_payload = new_request_payload(
            &initial_request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: initial_request_payload,
                },
                test_peer,
            )
            .unwrap();
        read_single_response(&handler);

        let repeated_hash_request_id = new_jsonrpc_request_id();
        let repeated_hash_payload = new_request_payload(
            &repeated_hash_request_id,
            &[
                (
                    3,
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ),
                (
                    4,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: repeated_hash_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["id"], repeated_hash_request_id);
        assert_eq!(
            response_value["error"]["code"],
            ASYNC_ERROR_DUPLICATE_HASH_CONFLICT
        );
        assert_eq!(
            response_value["error"]["message"],
            "duplicate_hash_conflict"
        );
    }

    #[test]
    fn async_order_new_rejects_malformed_json_with_parse_error() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(4);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: "{".to_owned(),
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], Value::Null);
        assert_eq!(response_value["error"]["code"], JSONRPC_PARSE_ERROR);
        assert_eq!(response_value["error"]["message"], "parse error");
    }

    #[test]
    fn async_order_new_rejects_notification_like_payload_with_parse_error() {
        let handler = AsyncOrderMessageHandler::new();
        let test_peer = test_peer_pubkey(5);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "method": "async_order.new",
                        "params": {
                            "protocol_version": PROTOCOL_VERSION,
                            "hashes": [
                                {
                                    "hash_index": "1",
                                    "payment_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }
                            ],
                        },
                    })
                    .to_string(),
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], Value::Null);
        assert_eq!(response_value["error"]["code"], JSONRPC_PARSE_ERROR);
        assert_eq!(response_value["error"]["message"], "parse error");
    }
}
