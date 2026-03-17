// NOTE: This module mirrors core behavior from `src/routes.rs` for SDK consumers.
// If route-level business logic changes, keep SDK equivalents in sync.

use crate::error::APIError;
use crate::core_types::{
    HtlcStatus as CoreHtlcStatus, SwapStatus as CoreSwapStatus,
    UnlockRequestData as CoreUnlockRequestData,
};
use crate::disk::{self, CHANNEL_PEER_DATA};
use crate::ldk::{start_ldk, PaymentInfo, FEE_RATE, MIN_CHANNEL_CONFIRMATIONS};
use crate::rgb::check_rgb_proxy_endpoint;
use crate::swap::SwapData;
use crate::utils::{
    check_already_initialized, check_channel_id, check_password_strength, check_password_validity,
    connect_peer_if_necessary, encrypt_and_save_mnemonic, get_current_timestamp, get_mnemonic_path,
    hex_str, hex_str_to_vec, parse_peer_info, AppState,
};
use amplify::{map, s};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::ScriptBuf;
use lightning::chain::channelmonitor::Balance;
use lightning::ln::channel_state::ChannelShutdownState;
use lightning::ln::channelmanager::Bolt11InvoiceParameters;
use lightning::ln::channelmanager::{OptionalOfferPaymentParams, PaymentId, Retry};
use lightning::offers::offer::{self, Offer};
use lightning::rgb_utils::{
    get_rgb_channel_info_path, get_rgb_payment_info_path, parse_rgb_channel_info, parse_rgb_payment_info,
    write_rgb_channel_info, write_rgb_payment_info_file, RgbInfo, STATIC_BLINDING,
};
use lightning::routing::gossip::NodeId;
use lightning::routing::router::RouteParametersConfig;
use lightning::sign::EntropySource;
use lightning::types::payment::PaymentHash;
use lightning::util::config::{ChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig};
use lightning::util::errors::APIError as LDKAPIError;
use lightning::impl_writeable_tlv_based_enum;
use lightning_invoice::Bolt11Invoice;
use regex::Regex;
use rgb_lib::wallet::rust_only::check_indexer_url as rgb_lib_check_indexer_url;
use rgb_lib::wallet::{Invoice as RgbLibInvoice, Recipient as RgbLibRecipient, RecipientInfo, WitnessData as RgbLibWitnessData};
use rgb_lib::{bdk_wallet::keys::bip39::Mnemonic, generate_keys, ContractId, RgbTransport};
use rgb_lib::utils::recipient_id_from_script_buf;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};

use rgb_lib::wallet::rust_only::IndexerProtocol as RgbLibIndexerProtocol;
use rgb_lib::wallet::RecipientType as RgbLibRecipientType;
use rgb_lib::wallet::{
    AssetCFA as RgbLibAssetCFA, AssetNIA as RgbLibAssetNIA, AssetUDA as RgbLibAssetUDA,
    EmbeddedMedia as RgbLibEmbeddedMedia, Media as RgbLibMedia,
    ProofOfReserves as RgbLibProofOfReserves, Token as RgbLibToken, TokenLight as RgbLibTokenLight,
};
use rgb_lib::BitcoinNetwork as RgbBitcoinNetwork;
use rgb_lib::{AssetSchema as RgbLibAssetSchema, Assignment as RgbLibAssignment};
use serde::{Deserialize, Serialize};

const SDK_HTLC_MIN_MSAT: u64 = 3_000_000;
const SDK_OPENRGBCHANNEL_MIN_SAT: u64 = SDK_HTLC_MIN_MSAT / 1000 * 10 + 10;
const SDK_OPENCHANNEL_MIN_SAT: u64 = 5506;
const SDK_OPENCHANNEL_MAX_SAT: u64 = 16_777_215;
const SDK_OPENCHANNEL_MIN_RGB_AMT: u64 = 1;
const SDK_INVOICE_MIN_MSAT: u64 = SDK_HTLC_MIN_MSAT;

pub(crate) struct NodeInfoData {
    pub(crate) pubkey: String,
    pub(crate) num_channels: usize,
    pub(crate) num_usable_channels: usize,
    pub(crate) local_balance_sat: u64,
    pub(crate) eventual_close_fees_sat: u64,
    pub(crate) pending_outbound_payments_sat: u64,
    pub(crate) num_peers: usize,
    pub(crate) account_xpub_vanilla: String,
    pub(crate) account_xpub_colored: String,
    pub(crate) network_nodes: usize,
    pub(crate) network_channels: usize,
}

pub(crate) struct NetworkInfoData {
    pub(crate) network: RgbBitcoinNetwork,
    pub(crate) height: u32,
}

pub(crate) struct AddressData {
    pub(crate) address: String,
}

pub(crate) struct AssetBalanceData {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
    pub(crate) offchain_outbound: u64,
    pub(crate) offchain_inbound: u64,
}

pub(crate) struct AssetMetadataData {
    pub(crate) asset_schema: RgbLibAssetSchema,
    pub(crate) initial_supply: u64,
    pub(crate) max_supply: u64,
    pub(crate) known_circulating_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) name: String,
    pub(crate) precision: u8,
    pub(crate) ticker: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) token: Option<Token>,
}

pub(crate) struct BtcBalance {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
}

pub(crate) struct BtcBalanceData {
    pub(crate) vanilla: BtcBalance,
    pub(crate) colored: BtcBalance,
}

pub(crate) struct DecodeLnInvoiceData {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) expiry_sec: u64,
    pub(crate) timestamp: u64,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) payee_pubkey: Option<String>,
    pub(crate) network: RgbBitcoinNetwork,
}

pub(crate) struct DecodeRgbInvoiceData {
    pub(crate) recipient_id: String,
    pub(crate) recipient_type: RgbLibRecipientType,
    pub(crate) asset_schema: Option<RgbLibAssetSchema>,
    pub(crate) asset_id: Option<String>,
    pub(crate) assignment: RgbLibAssignment,
    pub(crate) network: RgbBitcoinNetwork,
    pub(crate) expiration_timestamp: Option<i64>,
    pub(crate) transport_endpoints: Vec<String>,
}

pub(crate) struct EstimateFeeData {
    pub(crate) fee_rate: f64,
}

pub(crate) struct AssetMediaData {
    pub(crate) bytes_hex: String,
}

pub(crate) struct ChannelIdData {
    pub(crate) channel_id: String,
}

pub(crate) struct InvoiceStatusData {
    pub(crate) status: InvoiceStatus,
}

pub(crate) struct CheckIndexerUrlData {
    pub(crate) indexer_protocol: RgbLibIndexerProtocol,
}

pub(crate) struct SignMessageData {
    pub(crate) signed_message: String,
}

pub(crate) struct SendRgbData {
    pub(crate) txid: String,
    pub(crate) batch_transfer_idx: i32,
}

pub(crate) enum AssignmentKindData {
    Fungible,
    NonFungible,
    InflationRight,
    ReplaceRight,
    Any,
}

pub(crate) struct WitnessDataInput {
    pub(crate) amount_sat: u64,
    pub(crate) blinding: Option<u64>,
}

pub(crate) struct RecipientInput {
    pub(crate) recipient_id: String,
    pub(crate) witness_data: Option<WitnessDataInput>,
    pub(crate) assignment_kind: AssignmentKindData,
    pub(crate) assignment_amount: Option<u64>,
    pub(crate) transport_endpoints: Vec<String>,
}

pub(crate) struct AssetRecipientsInput {
    pub(crate) asset_id: String,
    pub(crate) recipients: Vec<RecipientInput>,
}

pub(crate) struct SendRgbRequestData {
    pub(crate) donation: bool,
    pub(crate) fee_rate: u64,
    pub(crate) min_confirmations: u8,
    pub(crate) skip_sync: bool,
    pub(crate) recipient_groups: Vec<AssetRecipientsInput>,
}

pub(crate) struct InitData {
    pub(crate) mnemonic: String,
}

pub(crate) struct UnlockRequestData {
    pub(crate) password: String,
    pub(crate) bitcoind_rpc_username: String,
    pub(crate) bitcoind_rpc_password: String,
    pub(crate) bitcoind_rpc_host: String,
    pub(crate) bitcoind_rpc_port: u16,
    pub(crate) indexer_url: Option<String>,
    pub(crate) proxy_endpoint: Option<String>,
    pub(crate) announce_addresses: Vec<String>,
    pub(crate) announce_alias: Option<String>,
}

pub(crate) struct OpenChannelRequestData {
    pub(crate) peer_pubkey_and_opt_addr: String,
    pub(crate) capacity_sat: u64,
    pub(crate) push_msat: u64,
    pub(crate) public: bool,
    pub(crate) with_anchors: bool,
    pub(crate) fee_base_msat: Option<u32>,
    pub(crate) fee_proportional_millionths: Option<u32>,
    pub(crate) temporary_channel_id: Option<String>,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

pub(crate) struct OpenChannelData {
    pub(crate) temporary_channel_id: String,
}

pub(crate) struct SendPaymentRequestData {
    pub(crate) invoice: String,
    pub(crate) amt_msat: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

pub(crate) struct SendPaymentData {
    pub(crate) payment_id: String,
    pub(crate) payment_hash: Option<String>,
    pub(crate) payment_secret: Option<String>,
    pub(crate) status: HtlcStatus,
}

pub(crate) struct ListAssetsData {
    pub(crate) nia: Option<Vec<AssetNIA>>,
    pub(crate) uda: Option<Vec<AssetUDA>>,
    pub(crate) cfa: Option<Vec<AssetCFA>>,
}

pub(crate) struct LnInvoiceData {
    pub(crate) invoice: String,
}

pub(crate) struct PaymentData {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) payment_hash: String,
    pub(crate) inbound: bool,
    pub(crate) status: HtlcStatus,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) payee_pubkey: String,
}

pub(crate) struct ChannelData {
    pub(crate) channel_id: String,
    pub(crate) funding_txid: Option<String>,
    pub(crate) peer_pubkey: String,
    pub(crate) peer_alias: Option<String>,
    pub(crate) short_channel_id: Option<u64>,
    pub(crate) status: ChannelStatus,
    pub(crate) ready: bool,
    pub(crate) capacity_sat: u64,
    pub(crate) local_balance_sat: u64,
    pub(crate) outbound_balance_msat: u64,
    pub(crate) inbound_balance_msat: u64,
    pub(crate) next_outbound_htlc_limit_msat: u64,
    pub(crate) next_outbound_htlc_minimum_msat: u64,
    pub(crate) is_usable: bool,
    pub(crate) public: bool,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_local_amount: Option<u64>,
    pub(crate) asset_remote_amount: Option<u64>,
}

pub(crate) struct TransactionData {
    pub(crate) transaction_type: TransactionType,
    pub(crate) txid: String,
    pub(crate) received: u64,
    pub(crate) sent: u64,
    pub(crate) fee: u64,
    pub(crate) confirmation_time: Option<BlockTime>,
}

pub(crate) struct TransferTransportEndpointData {
    pub(crate) endpoint: String,
    pub(crate) transport_type: TransportType,
    pub(crate) used: bool,
}

pub(crate) struct TransferData {
    pub(crate) idx: i32,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) status: TransferStatus,
    pub(crate) requested_assignment: Option<RgbLibAssignment>,
    pub(crate) assignments: Vec<RgbLibAssignment>,
    pub(crate) kind: TransferKind,
    pub(crate) txid: Option<String>,
    pub(crate) recipient_id: Option<String>,
    pub(crate) receive_utxo: Option<String>,
    pub(crate) change_utxo: Option<String>,
    pub(crate) expiration: Option<i64>,
    pub(crate) transport_endpoints: Vec<TransferTransportEndpointData>,
}

pub(crate) struct RgbAllocationData {
    pub(crate) asset_id: Option<String>,
    pub(crate) assignment: RgbLibAssignment,
    pub(crate) settled: bool,
}

pub(crate) struct UtxoData {
    pub(crate) outpoint: String,
    pub(crate) btc_amount: u64,
    pub(crate) colorable: bool,
}

pub(crate) struct UnspentData {
    pub(crate) utxo: UtxoData,
    pub(crate) rgb_allocations: Vec<RgbAllocationData>,
}

pub(crate) struct PeerData {
    pub(crate) pubkey: String,
}

pub(crate) struct SwapViewData {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<String>,
    pub(crate) to_asset: Option<String>,
    pub(crate) payment_hash: String,
    pub(crate) status: SwapStatus,
    pub(crate) requested_at: u64,
    pub(crate) initiated_at: Option<u64>,
    pub(crate) expires_at: u64,
    pub(crate) completed_at: Option<u64>,
}

pub(crate) struct SwapListData {
    pub(crate) taker: Vec<SwapViewData>,
    pub(crate) maker: Vec<SwapViewData>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum ChannelStatus {
    #[default]
    Opening,
    Opened,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub(crate) enum HtlcStatus {
    Pending,
    Succeeded,
    Failed,
}

impl std::fmt::Display for HtlcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            HtlcStatus::Pending => "Pending",
            HtlcStatus::Succeeded => "Succeeded",
            HtlcStatus::Failed => "Failed",
        };
        write!(f, "{label}")
    }
}

impl_writeable_tlv_based_enum!(HtlcStatus,
    (0, Pending) => {},
    (1, Succeeded) => {},
    (2, Failed) => {},
);

impl From<CoreHtlcStatus> for HtlcStatus {
    fn from(value: CoreHtlcStatus) -> Self {
        match value {
            CoreHtlcStatus::Pending => Self::Pending,
            CoreHtlcStatus::Succeeded => Self::Succeeded,
            CoreHtlcStatus::Failed => Self::Failed,
        }
    }
}

impl From<HtlcStatus> for CoreHtlcStatus {
    fn from(value: HtlcStatus) -> Self {
        match value {
            HtlcStatus::Pending => Self::Pending,
            HtlcStatus::Succeeded => Self::Succeeded,
            HtlcStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InvoiceStatus {
    Pending,
    Succeeded,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum SwapStatus {
    Waiting,
    Pending,
    Succeeded,
    Expired,
    Failed,
}

impl_writeable_tlv_based_enum!(SwapStatus,
    (0, Waiting) => {},
    (1, Pending) => {},
    (2, Succeeded) => {},
    (3, Expired) => {},
    (4, Failed) => {},
);

impl From<CoreSwapStatus> for SwapStatus {
    fn from(value: CoreSwapStatus) -> Self {
        match value {
            CoreSwapStatus::Waiting => Self::Waiting,
            CoreSwapStatus::Pending => Self::Pending,
            CoreSwapStatus::Succeeded => Self::Succeeded,
            CoreSwapStatus::Expired => Self::Expired,
            CoreSwapStatus::Failed => Self::Failed,
        }
    }
}

impl From<SwapStatus> for CoreSwapStatus {
    fn from(value: SwapStatus) -> Self {
        match value {
            SwapStatus::Waiting => Self::Waiting,
            SwapStatus::Pending => Self::Pending,
            SwapStatus::Succeeded => Self::Succeeded,
            SwapStatus::Expired => Self::Expired,
            SwapStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Debug)]
pub(crate) struct BlockTime {
    pub(crate) height: u32,
    pub(crate) timestamp: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransactionType {
    RgbSend,
    Drain,
    CreateUtxos,
    User,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransferKind {
    Issuance,
    ReceiveBlind,
    ReceiveWitness,
    Send,
    Inflation,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransferStatus {
    WaitingCounterparty,
    WaitingConfirmations,
    Settled,
    Failed,
}

#[derive(Debug)]
pub(crate) enum TransportType {
    JsonRpc,
}

pub(crate) struct EmbeddedMedia {
    pub(crate) mime: String,
    pub(crate) data: Vec<u8>,
}

impl From<RgbLibEmbeddedMedia> for EmbeddedMedia {
    fn from(value: RgbLibEmbeddedMedia) -> Self {
        Self {
            mime: value.mime,
            data: value.data,
        }
    }
}

pub(crate) struct Media {
    pub(crate) file_path: String,
    pub(crate) digest: String,
    pub(crate) mime: String,
}

impl From<RgbLibMedia> for Media {
    fn from(value: RgbLibMedia) -> Self {
        Self {
            file_path: value.file_path,
            digest: value.digest,
            mime: value.mime,
        }
    }
}

pub(crate) struct ProofOfReserves {
    pub(crate) utxo: String,
    pub(crate) proof: Vec<u8>,
}

impl From<RgbLibProofOfReserves> for ProofOfReserves {
    fn from(value: RgbLibProofOfReserves) -> Self {
        Self {
            utxo: value.utxo.to_string(),
            proof: value.proof,
        }
    }
}

pub(crate) struct Token {
    pub(crate) index: u32,
    pub(crate) ticker: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) embedded_media: Option<EmbeddedMedia>,
    pub(crate) media: Option<Media>,
    pub(crate) attachments: HashMap<u8, Media>,
    pub(crate) reserves: Option<ProofOfReserves>,
}

impl From<RgbLibToken> for Token {
    fn from(value: RgbLibToken) -> Self {
        Self {
            index: value.index,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            embedded_media: value.embedded_media.map(Into::into),
            media: value.media.map(Into::into),
            attachments: value
                .attachments
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            reserves: value.reserves.map(Into::into),
        }
    }
}

pub(crate) struct TokenLight {
    pub(crate) index: u32,
    pub(crate) ticker: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) embedded_media: bool,
    pub(crate) media: Option<Media>,
    pub(crate) attachments: HashMap<u8, Media>,
    pub(crate) reserves: bool,
}

impl From<RgbLibTokenLight> for TokenLight {
    fn from(value: RgbLibTokenLight) -> Self {
        Self {
            index: value.index,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            embedded_media: value.embedded_media,
            media: value.media.map(Into::into),
            attachments: value
                .attachments
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            reserves: value.reserves,
        }
    }
}

pub(crate) struct AssetBalance {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
    pub(crate) offchain_outbound: u64,
    pub(crate) offchain_inbound: u64,
}

pub(crate) struct AssetNIA {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) issued_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) media: Option<Media>,
}

impl From<RgbLibAssetNIA> for AssetNIA {
    fn from(value: RgbLibAssetNIA) -> Self {
        Self {
            asset_id: value.asset_id,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            precision: value.precision,
            issued_supply: value.issued_supply,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            media: value.media.map(Into::into),
        }
    }
}

pub(crate) struct AssetUDA {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) token: Option<TokenLight>,
}

impl From<RgbLibAssetUDA> for AssetUDA {
    fn from(value: RgbLibAssetUDA) -> Self {
        Self {
            asset_id: value.asset_id,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            precision: value.precision,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            token: value.token.map(Into::into),
        }
    }
}

pub(crate) struct AssetCFA {
    pub(crate) asset_id: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) issued_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) media: Option<Media>,
}

impl From<RgbLibAssetCFA> for AssetCFA {
    fn from(value: RgbLibAssetCFA) -> Self {
        Self {
            asset_id: value.asset_id,
            name: value.name,
            details: value.details,
            precision: value.precision,
            issued_supply: value.issued_supply,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            media: value.media.map(Into::into),
        }
    }
}

/*
 * -------------------------------------------------------------------------
 * ROUTES-PARITY METHODS
 * -------------------------------------------------------------------------
 * The async functions below intentionally mirror business logic from
 * `src/routes.rs` (same validations and core behavior, SDK-shaped inputs/outputs).
 * When route logic changes, review and update the corresponding method here.
 */

pub(crate) async fn estimate_fee(
    state: Arc<AppState>,
    blocks: u16,
) -> Result<EstimateFeeData, APIError> {
    let fee_rate = state
        .check_unlocked()
        .await?
        .clone()
        .unwrap()
        .rgb_get_fee_estimation(blocks)?;
    Ok(EstimateFeeData { fee_rate })
}

pub(crate) async fn check_indexer_url(
    state: Arc<AppState>,
    indexer_url: String,
) -> Result<CheckIndexerUrlData, APIError> {
    let indexer_protocol = rgb_lib_check_indexer_url(&indexer_url, state.static_state.network)?;
    Ok(CheckIndexerUrlData { indexer_protocol })
}

pub(crate) async fn check_proxy_endpoint(proxy_endpoint: String) -> Result<(), APIError> {
    check_rgb_proxy_endpoint(&proxy_endpoint).await?;
    Ok(())
}


pub(crate) async fn node_info(state: Arc<AppState>) -> Result<NodeInfoData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let chans = unlocked_state.channel_manager.list_channels();

    let balances = unlocked_state.chain_monitor.get_claimable_balances(&[]);
    let local_balance_sat = balances
        .iter()
        .map(|b| b.claimable_amount_satoshis())
        .sum::<u64>();

    let close_fees_map = |b| match b {
        &Balance::ClaimableOnChannelClose {
            ref balance_candidates,
            confirmed_balance_candidate_index,
            ..
        } => balance_candidates[confirmed_balance_candidate_index].transaction_fee_satoshis,
        _ => 0,
    };
    let eventual_close_fees_sat = balances.iter().map(close_fees_map).sum::<u64>();

    let pending_payments_map = |b| match b {
        &Balance::MaybeTimeoutClaimableHTLC {
            amount_satoshis,
            outbound_payment,
            ..
        } => {
            if outbound_payment {
                amount_satoshis
            } else {
                0
            }
        }
        _ => 0,
    };
    let pending_outbound_payments_sat = balances.iter().map(pending_payments_map).sum::<u64>();

    let graph_lock = unlocked_state.network_graph.read_only();
    let network_nodes = graph_lock.nodes().len();
    let network_channels = graph_lock.channels().len();

    let wallet_data = unlocked_state.rgb_get_wallet_data();

    Ok(NodeInfoData {
        pubkey: unlocked_state.channel_manager.get_our_node_id().to_string(),
        num_channels: chans.len(),
        num_usable_channels: chans.iter().filter(|c| c.is_usable).count(),
        local_balance_sat,
        eventual_close_fees_sat,
        pending_outbound_payments_sat,
        num_peers: unlocked_state.peer_manager.list_peers().len(),
        account_xpub_vanilla: wallet_data.account_xpub_vanilla,
        account_xpub_colored: wallet_data.account_xpub_colored,
        network_nodes,
        network_channels,
    })
}

pub(crate) async fn network_info(state: Arc<AppState>) -> Result<NetworkInfoData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();
    let best_block = unlocked_state.channel_manager.current_best_block();

    Ok(NetworkInfoData {
        network: state.static_state.network,
        height: best_block.height,
    })
}

pub(crate) async fn address(state: Arc<AppState>) -> Result<AddressData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    Ok(AddressData {
        address: unlocked_state.rgb_get_address()?,
    })
}

pub(crate) async fn btc_balance(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<BtcBalanceData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();
    let btc_balance = unlocked_state.rgb_get_btc_balance(skip_sync)?;

    Ok(BtcBalanceData {
        vanilla: BtcBalance {
            settled: btc_balance.vanilla.settled,
            future: btc_balance.vanilla.future,
            spendable: btc_balance.vanilla.spendable,
        },
        colored: BtcBalance {
            settled: btc_balance.colored.settled,
            future: btc_balance.colored.future,
            spendable: btc_balance.colored.spendable,
        },
    })
}

pub(crate) async fn sign_message(
    state: Arc<AppState>,
    message: String,
) -> Result<SignMessageData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let trimmed = message.trim();
    let signed_message = lightning::util::message_signing::sign(
        trimmed.as_bytes(),
        &unlocked_state.keys_manager.get_node_secret_key(),
    );
    Ok(SignMessageData { signed_message })
}


pub(crate) async fn get_channel_id(
    state: Arc<AppState>,
    temporary_channel_id: String,
) -> Result<ChannelIdData, APIError> {
    let tmp_chan_id = check_channel_id(&temporary_channel_id)?;
    let channel_ids = state.check_unlocked().await?.clone().unwrap().channel_ids();
    let channel_id = channel_ids
        .get(&tmp_chan_id)
        .map(|channel_id| channel_id.0.as_hex().to_string())
        .ok_or(APIError::UnknownTemporaryChannelId)?;

    Ok(ChannelIdData { channel_id })
}

pub(crate) async fn list_channels(state: Arc<AppState>) -> Result<Vec<ChannelData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut channels = vec![];
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let status = match chan_info.channel_shutdown_state.unwrap() {
            ChannelShutdownState::NotShuttingDown => {
                if chan_info.is_channel_ready {
                    ChannelStatus::Opened
                } else {
                    ChannelStatus::Opening
                }
            }
            _ => ChannelStatus::Closing,
        };
        let mut channel = ChannelData {
            channel_id: chan_info.channel_id.0.as_hex().to_string(),
            peer_pubkey: hex_str(&chan_info.counterparty.node_id.serialize()),
            status,
            ready: chan_info.is_channel_ready,
            capacity_sat: chan_info.channel_value_satoshis,
            local_balance_sat: 0,
            outbound_balance_msat: chan_info.outbound_capacity_msat,
            inbound_balance_msat: chan_info.inbound_capacity_msat,
            next_outbound_htlc_limit_msat: chan_info.next_outbound_htlc_limit_msat,
            next_outbound_htlc_minimum_msat: chan_info.next_outbound_htlc_minimum_msat,
            is_usable: chan_info.is_usable,
            public: chan_info.is_announced,
            funding_txid: None,
            peer_alias: None,
            short_channel_id: None,
            asset_id: None,
            asset_local_amount: None,
            asset_remote_amount: None,
        };

        if let Some(funding_txo) = chan_info.funding_txo {
            channel.funding_txid = Some(funding_txo.txid.to_string());
            if let Ok(chan_monitor) = unlocked_state
                .chain_monitor
                .get_monitor(chan_info.channel_id)
            {
                channel.local_balance_sat = chan_monitor
                    .get_claimable_balances()
                    .iter()
                    .map(|b| b.claimable_amount_satoshis())
                    .sum::<u64>();
            }
        }

        if let Some(node_info) = unlocked_state
            .network_graph
            .read_only()
            .nodes()
            .get(&NodeId::from_pubkey(&chan_info.counterparty.node_id))
        {
            if let Some(announcement) = &node_info.announcement_info {
                channel.peer_alias = Some(announcement.alias().to_string());
            }
        }

        channel.short_channel_id = chan_info.short_channel_id;

        let info_file_path = get_rgb_channel_info_path(
            &chan_info.channel_id.0.as_hex().to_string(),
            &state.static_state.ldk_data_dir,
            false,
        );
        if info_file_path.exists() {
            let rgb_info = parse_rgb_channel_info(&info_file_path);
            channel.asset_id = Some(rgb_info.contract_id.to_string());
            channel.asset_local_amount = Some(rgb_info.local_rgb_amount);
            channel.asset_remote_amount = Some(rgb_info.remote_rgb_amount);
        }

        channels.push(channel);
    }

    Ok(channels)
}

pub(crate) async fn list_peers(state: Arc<AppState>) -> Result<Vec<PeerData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    Ok(unlocked_state
        .peer_manager
        .list_peers()
        .into_iter()
        .map(|peer_details| PeerData {
            pubkey: peer_details.counterparty_node_id.to_string(),
        })
        .collect())
}


pub(crate) async fn asset_balance(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<AssetBalanceData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;
    let balance = unlocked_state.rgb_get_asset_balance(contract_id)?;

    let mut offchain_outbound = 0;
    let mut offchain_inbound = 0;
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let info_file_path = get_rgb_channel_info_path(
            &chan_info.channel_id.0.as_hex().to_string(),
            &state.static_state.ldk_data_dir,
            false,
        );
        if !info_file_path.exists() {
            continue;
        }
        let rgb_info = parse_rgb_channel_info(&info_file_path);
        if rgb_info.contract_id == contract_id {
            offchain_outbound += rgb_info.local_rgb_amount;
            offchain_inbound += rgb_info.remote_rgb_amount;
        }
    }

    Ok(AssetBalanceData {
        settled: balance.settled,
        future: balance.future,
        spendable: balance.spendable,
        offchain_outbound,
        offchain_inbound,
    })
}

pub(crate) async fn asset_metadata(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<AssetMetadataData, APIError> {
    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;
    let metadata = state
        .check_unlocked()
        .await?
        .clone()
        .unwrap()
        .rgb_get_asset_metadata(contract_id)?;

    Ok(AssetMetadataData {
        asset_schema: metadata.asset_schema,
        initial_supply: metadata.initial_supply,
        max_supply: metadata.max_supply,
        known_circulating_supply: metadata.known_circulating_supply,
        timestamp: metadata.timestamp,
        name: metadata.name,
        precision: metadata.precision,
        ticker: metadata.ticker,
        details: metadata.details,
        token: metadata.token.map(Into::into),
    })
}

pub(crate) async fn get_asset_media(
    state: Arc<AppState>,
    digest: String,
) -> Result<AssetMediaData, APIError> {
    let file_path = state
        .check_unlocked()
        .await?
        .clone()
        .unwrap()
        .rgb_get_media_dir()
        .join(digest.to_lowercase());
    if !file_path.exists() {
        return Err(APIError::InvalidMediaDigest);
    }

    let mut buf_reader = BufReader::new(File::open(file_path).await?);
    let mut file_bytes = Vec::new();
    buf_reader.read_to_end(&mut file_bytes).await?;

    Ok(AssetMediaData {
        bytes_hex: hex_str(&file_bytes),
    })
}

pub(crate) async fn list_assets(
    state: Arc<AppState>,
    filter_asset_schemas: Vec<rgb_lib::AssetSchema>,
) -> Result<ListAssetsData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let rgb_assets = unlocked_state.rgb_list_assets(filter_asset_schemas)?;

    let mut offchain_balances = HashMap::new();
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let info_file_path = get_rgb_channel_info_path(
            &chan_info.channel_id.0.as_hex().to_string(),
            &state.static_state.ldk_data_dir,
            false,
        );
        if !info_file_path.exists() {
            continue;
        }
        let rgb_info = parse_rgb_channel_info(&info_file_path);
        offchain_balances
            .entry(rgb_info.contract_id.to_string())
            .and_modify(|(offchain_outbound, offchain_inbound)| {
                *offchain_outbound += rgb_info.local_rgb_amount;
                *offchain_inbound += rgb_info.remote_rgb_amount;
            })
            .or_insert((rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount));
    }

    let nia = rgb_assets.nia.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetNIA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });
    let uda = rgb_assets.uda.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetUDA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });
    let cfa = rgb_assets.cfa.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetCFA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });

    Ok(ListAssetsData { nia, uda, cfa })
}

pub(crate) async fn send_rgb(
    state: Arc<AppState>,
    recipient_map: HashMap<String, Vec<rgb_lib::wallet::Recipient>>,
    donation: bool,
    fee_rate: u64,
    min_confirmations: u8,
    skip_sync: bool,
) -> Result<SendRgbData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let unlocked_state_copy = unlocked_state.clone();
    let send_result = tokio::task::spawn_blocking(move || {
        unlocked_state_copy.rgb_send(
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            skip_sync,
        )
    })
    .await
    .unwrap()?;

    Ok(SendRgbData {
        txid: send_result.txid,
        batch_transfer_idx: send_result.batch_transfer_idx,
    })
}

pub(crate) async fn send_rgb_from_groups(
    state: Arc<AppState>,
    request: SendRgbRequestData,
) -> Result<SendRgbData, APIError> {
    if request.recipient_groups.is_empty() {
        return Err(APIError::InvalidAmount("recipient_groups cannot be empty".to_string()));
    }

    let recipient_map = request
        .recipient_groups
        .into_iter()
        .map(|group| {
            let recipients = group
                .recipients
                .into_iter()
                .map(|r| {
                    let assignment = match (r.assignment_kind, r.assignment_amount) {
                        (AssignmentKindData::Fungible, Some(v)) => RgbLibAssignment::Fungible(v),
                        (AssignmentKindData::InflationRight, Some(v)) => {
                            RgbLibAssignment::InflationRight(v)
                        }
                        (AssignmentKindData::NonFungible, None) => RgbLibAssignment::NonFungible,
                        (AssignmentKindData::ReplaceRight, None) => RgbLibAssignment::ReplaceRight,
                        (AssignmentKindData::Any, None) => RgbLibAssignment::Any,
                        _ => {
                            return Err(APIError::InvalidAmount(
                                "invalid RGB assignment payload".to_string(),
                            ))
                        }
                    };
                    let recipient = RgbLibRecipient {
                        recipient_id: r.recipient_id,
                        witness_data: r.witness_data.map(|w| RgbLibWitnessData {
                            amount_sat: w.amount_sat,
                            blinding: w.blinding,
                        }),
                        assignment,
                        transport_endpoints: r.transport_endpoints,
                    };
                    Ok::<RgbLibRecipient, APIError>(recipient)
                })
                .collect::<Result<Vec<_>, APIError>>()?;
            Ok((group.asset_id, recipients))
        })
        .collect::<Result<HashMap<_, _>, APIError>>()?;

    send_rgb(
        state,
        recipient_map,
        request.donation,
        request.fee_rate,
        request.min_confirmations,
        request.skip_sync,
    )
    .await
}

pub(crate) async fn init(
    state: Arc<AppState>,
    password: String,
    mnemonic: Option<String>,
) -> Result<InitData, APIError> {
    let _unlocked_state = state.check_locked().await?;

    check_password_strength(password.clone())?;
    let mnemonic_path = get_mnemonic_path(&state.static_state.storage_dir_path);
    check_already_initialized(&mnemonic_path)?;

    let mnemonic = match mnemonic {
        Some(mnemonic) => Mnemonic::from_str(&mnemonic)
            .map_err(|e| APIError::InvalidMnemonic(e.to_string()))?
            .to_string(),
        None => generate_keys(state.static_state.network).mnemonic,
    };

    encrypt_and_save_mnemonic(password, mnemonic.clone(), &mnemonic_path)?;
    Ok(InitData { mnemonic })
}

pub(crate) async fn unlock(
    state: Arc<AppState>,
    request: UnlockRequestData,
) -> Result<(), APIError> {
    tracing::info!("Unlock started");
    match state.check_locked().await {
        Ok(unlocked_state) => {
            state.update_changing_state(true);
            drop(unlocked_state);
        }
        Err(e) => {
            return Err(match e {
                APIError::UnlockedNode => APIError::AlreadyUnlocked,
                _ => e,
            });
        }
    }

    let mnemonic = match check_password_validity(&request.password, &state.static_state.storage_dir_path)
    {
        Ok(mnemonic) => mnemonic,
        Err(e) => {
            state.update_changing_state(false);
            return Err(e);
        }
    };

    tracing::debug!("Starting LDK...");
    let unlock_request = CoreUnlockRequestData {
        bitcoind_rpc_username: request.bitcoind_rpc_username,
        bitcoind_rpc_password: request.bitcoind_rpc_password,
        bitcoind_rpc_host: request.bitcoind_rpc_host,
        bitcoind_rpc_port: request.bitcoind_rpc_port,
        indexer_url: request.indexer_url,
        proxy_endpoint: request.proxy_endpoint,
        announce_addresses: request.announce_addresses,
        announce_alias: request.announce_alias,
    };
    let (new_ldk_background_services, new_unlocked_app_state) =
        match start_ldk(state.clone(), mnemonic, unlock_request).await {
            Ok((nlbs, nuap)) => (nlbs, nuap),
            Err(e) => {
                state.update_changing_state(false);
                return Err(e);
            }
        };
    tracing::debug!("LDK started");

    state
        .update_unlocked_app_state(Some(new_unlocked_app_state))
        .await;
    state.update_ldk_background_services(Some(new_ldk_background_services));
    state.update_changing_state(false);
    tracing::info!("Unlock completed");
    Ok(())
}

pub(crate) async fn connect_peer(
    state: Arc<AppState>,
    peer_pubkey_and_addr: String,
) -> Result<(), APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let (peer_pubkey, peer_addr) = parse_peer_info(peer_pubkey_and_addr.to_string())?;

    if let Some(peer_addr) = peer_addr {
        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone()).await?;
        disk::persist_channel_peer(
            &state.static_state.ldk_data_dir.join(CHANNEL_PEER_DATA),
            &peer_pubkey,
            &peer_addr,
        )?;
    } else {
        return Err(APIError::InvalidPeerInfo(s!(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`"
        )));
    }

    Ok(())
}

pub(crate) async fn open_channel(
    state: Arc<AppState>,
    request: OpenChannelRequestData,
) -> Result<OpenChannelData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let temporary_channel_id = if let Some(tmp_chan_id_str) = request.temporary_channel_id {
        let tmp_chan_id = check_channel_id(&tmp_chan_id_str)?;
        if unlocked_state.channel_ids().contains_key(&tmp_chan_id) {
            return Err(APIError::TemporaryChannelIdAlreadyUsed);
        }
        Some(tmp_chan_id)
    } else {
        None
    };

    let colored_info = match (request.asset_id, request.asset_amount) {
        (Some(_), Some(amt)) if amt < SDK_OPENCHANNEL_MIN_RGB_AMT => {
            return Err(APIError::InvalidAmount(format!(
                "Channel RGB amount must be equal to or higher than {SDK_OPENCHANNEL_MIN_RGB_AMT}"
            )));
        }
        (Some(asset), Some(amt)) => {
            let asset = ContractId::from_str(&asset).map_err(|_| APIError::InvalidAssetID(asset))?;
            Some((asset, amt))
        }
        (None, None) => None,
        _ => return Err(APIError::IncompleteRGBInfo),
    };

    if colored_info.is_some() && request.capacity_sat < SDK_OPENRGBCHANNEL_MIN_SAT {
        return Err(APIError::InvalidAmount(format!(
            "RGB channel amount must be equal to or higher than {SDK_OPENRGBCHANNEL_MIN_SAT} sats"
        )));
    } else if request.capacity_sat < SDK_OPENCHANNEL_MIN_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal to or higher than {SDK_OPENCHANNEL_MIN_SAT} sats"
        )));
    }
    if request.capacity_sat > SDK_OPENCHANNEL_MAX_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal to or less than {SDK_OPENCHANNEL_MAX_SAT} sats"
        )));
    }

    if request.push_msat > request.capacity_sat * 1000 {
        return Err(APIError::InvalidAmount(s!(
            "Channel push amount cannot be higher than the capacity"
        )));
    }

    if colored_info.is_some() && !request.with_anchors {
        return Err(APIError::AnchorsRequired);
    }

    let (peer_pubkey, mut peer_addr) = parse_peer_info(request.peer_pubkey_and_opt_addr.to_string())?;

    let peer_data_path = state.static_state.ldk_data_dir.join(CHANNEL_PEER_DATA);
    if peer_addr.is_none() {
        if let Some(peer) = unlocked_state.peer_manager.peer_by_node_id(&peer_pubkey) {
            if let Some(socket_address) = peer.socket_address {
                if let Ok(mut socket_addrs) = socket_address.to_socket_addrs() {
                    peer_addr = socket_addrs.next();
                }
            }
        }
    }
    if peer_addr.is_none() {
        let peer_info = disk::read_channel_peer_data(&peer_data_path)?;
        for (pubkey, addr) in peer_info {
            if pubkey == peer_pubkey {
                peer_addr = Some(addr);
                break;
            }
        }
    }
    if let Some(peer_addr) = peer_addr {
        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone()).await?;
        disk::persist_channel_peer(&peer_data_path, &peer_pubkey, &peer_addr)?;
    } else {
        return Err(APIError::InvalidPeerInfo(s!(
            "cannot find the address for the provided pubkey"
        )));
    }

    let mut channel_config = ChannelConfig::default();
    if let Some(fee_base_msat) = request.fee_base_msat {
        channel_config.forwarding_fee_base_msat = fee_base_msat;
    }
    if let Some(fee_proportional_millionths) = request.fee_proportional_millionths {
        channel_config.forwarding_fee_proportional_millionths = fee_proportional_millionths;
    }
    let config = UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            announce_for_forwarding: request.public,
            our_htlc_minimum_msat: SDK_HTLC_MIN_MSAT,
            minimum_depth: MIN_CHANNEL_CONFIRMATIONS as u32,
            negotiate_anchors_zero_fee_htlc_tx: request.with_anchors,
            ..Default::default()
        },
        channel_config,
        ..Default::default()
    };

    let consignment_endpoint = if let Some((contract_id, asset_amount)) = &colored_info {
        let balance = unlocked_state.rgb_get_asset_balance(*contract_id)?;
        let spendable_rgb_amount = balance.spendable;
        if *asset_amount > spendable_rgb_amount {
            return Err(APIError::InsufficientAssets);
        }
        Some(RgbTransport::from_str(&unlocked_state.proxy_endpoint).unwrap())
    } else {
        None
    };

    let schema = if let Some((contract_id, asset_amount)) = &colored_info {
        let mut fake_p2wsh: [u8; 34] = [0; 34];
        fake_p2wsh[1] = 32;
        let script_buf = ScriptBuf::from_bytes(fake_p2wsh.to_vec());
        let recipient_id = recipient_id_from_script_buf(script_buf, state.static_state.network);
        let asset_id = contract_id.to_string();
        let schema = unlocked_state.rgb_get_asset_metadata(*contract_id)?.asset_schema;
        let assignment = match schema {
            RgbLibAssetSchema::Nia | RgbLibAssetSchema::Cfa => RgbLibAssignment::Fungible(*asset_amount),
            RgbLibAssetSchema::Uda => RgbLibAssignment::NonFungible,
            RgbLibAssetSchema::Ifa => todo!(),
        };

        let recipient_map = map! {
            asset_id => vec![RgbLibRecipient {
                recipient_id,
                witness_data: Some(RgbLibWitnessData {
                    amount_sat: request.capacity_sat,
                    blinding: Some(STATIC_BLINDING + 1),
                }),
                assignment,
                transport_endpoints: vec![unlocked_state.proxy_endpoint.clone()],
        }]};

        let unlocked_state_copy = unlocked_state.clone();
        tokio::task::spawn_blocking(move || {
            unlocked_state_copy.rgb_send_begin(
                recipient_map,
                true,
                FEE_RATE,
                MIN_CHANNEL_CONFIRMATIONS,
            )
        })
        .await
        .unwrap()?;
        Some(schema)
    } else {
        None
    };

    *unlocked_state.rgb_send_lock.lock().unwrap() = true;
    tracing::debug!("RGB send lock set to true");

    let temporary_channel_id = unlocked_state
        .channel_manager
        .create_channel(
            peer_pubkey,
            request.capacity_sat,
            request.push_msat,
            0,
            temporary_channel_id,
            Some(config),
            consignment_endpoint,
        )
        .map_err(|e| {
            *unlocked_state.rgb_send_lock.lock().unwrap() = false;
            tracing::debug!("RGB send lock set to false (open channel failure: {e:?})");
            match e {
                LDKAPIError::APIMisuseError { err }
                    if err.contains("fee for initial commitment transaction") =>
                {
                    let mut commitment_tx_fee = 0;
                    let re = Regex::new(r"fee for initial commitment transaction fee of (\d+).").unwrap();
                    if let Some(captures) = re.captures(&err) {
                        if let Some(fee_str) = captures.get(1) {
                            commitment_tx_fee = fee_str.as_str().parse().unwrap();
                        }
                    }
                    APIError::InsufficientCapacity(commitment_tx_fee)
                }
                _ => APIError::FailedOpenChannel(format!("{e:?}")),
            }
        })?;

    let temporary_channel_id = temporary_channel_id.0.as_hex().to_string();
    tracing::info!("EVENT: initiated channel with peer {}", peer_pubkey);

    if let Some((contract_id, asset_amount)) = &colored_info {
        let rgb_info = RgbInfo {
            contract_id: *contract_id,
            schema: schema.unwrap(),
            local_rgb_amount: *asset_amount,
            remote_rgb_amount: 0,
        };
        write_rgb_channel_info(
            &get_rgb_channel_info_path(&temporary_channel_id, &state.static_state.ldk_data_dir, true),
            &rgb_info,
        );
        write_rgb_channel_info(
            &get_rgb_channel_info_path(&temporary_channel_id, &state.static_state.ldk_data_dir, false),
            &rgb_info,
        );
    }

    Ok(OpenChannelData {
        temporary_channel_id,
    })
}

pub(crate) async fn send_payment(
    state: Arc<AppState>,
    request: SendPaymentRequestData,
) -> Result<SendPaymentData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut status = HtlcStatus::Pending;
    let created_at = get_current_timestamp();

    let (payment_id, payment_hash, payment_secret) =
        if let Ok(offer) = Offer::from_str(&request.invoice) {
            let random_bytes = unlocked_state.keys_manager.get_secure_random_bytes();
            let payment_id = PaymentId(random_bytes);

            let amt_msat = match (offer.amount(), request.amt_msat) {
                (Some(offer::Amount::Bitcoin { amount_msats }), _) => amount_msats,
                (_, Some(amt)) => amt,
                (amt, _) => {
                    return Err(APIError::InvalidAmount(format!(
                        "cannot process non-Bitcoin-denominated offer value {amt:?}"
                    )));
                }
            };
            if request.amt_msat.is_some() && request.amt_msat != Some(amt_msat) {
                return Err(APIError::InvalidAmount(format!(
                    "amount didn't match offer of {amt_msat}msat"
                )));
            }

            let secret = None;
            unlocked_state.add_outbound_payment(
                payment_id,
                PaymentInfo {
                    preimage: None,
                    secret,
                    status: status.into(),
                    amt_msat: Some(amt_msat),
                    created_at,
                    updated_at: created_at,
                    payee_pubkey: offer
                        .issuer_signing_pubkey()
                        .ok_or(APIError::InvalidInvoice(s!("missing signing pubkey")))?,
                    expires_at: None,
                },
            )?;

            let params = OptionalOfferPaymentParams {
                retry_strategy: Retry::Timeout(Duration::from_secs(10)),
                ..Default::default()
            };
            let pay = unlocked_state
                .channel_manager
                .pay_for_offer(&offer, Some(amt_msat), payment_id, params);
            if pay.is_err() {
                tracing::error!("ERROR: failed to pay: {:?}", pay);
                unlocked_state
                    .update_outbound_payment_status(payment_id, HtlcStatus::Failed.into());
                status = HtlcStatus::Failed;
                unlocked_state.update_outbound_payment_status(payment_id, status.into());
            }
            (payment_id, None, secret)
        } else {
            let invoice = Bolt11Invoice::from_str(&request.invoice)
                .map_err(|e| APIError::InvalidInvoice(e.to_string()))?;

            let payment_id = PaymentId((*invoice.payment_hash()).to_byte_array());
            let payment_secret = Some(*invoice.payment_secret());
            let zero_amt_invoice =
                invoice.amount_milli_satoshis().is_none() || invoice.amount_milli_satoshis() == Some(0);

            let amt_msat = if zero_amt_invoice {
                if let Some(amt_msat) = request.amt_msat {
                    amt_msat
                } else {
                    return Err(APIError::InvalidAmount(s!(
                        "need an amount for the given 0-value invoice"
                    )));
                }
            } else {
                if request.amt_msat.is_some() && invoice.amount_milli_satoshis() != request.amt_msat {
                    return Err(APIError::InvalidAmount(format!(
                        "amount didn't match invoice value of {}msat",
                        invoice.amount_milli_satoshis().unwrap_or(0)
                    )));
                }
                invoice.amount_milli_satoshis().unwrap_or(0)
            };

            let rgb_payment = match (invoice.rgb_contract_id(), invoice.rgb_amount()) {
                (Some(rgb_contract_id), Some(rgb_amount)) => {
                    if amt_msat < SDK_INVOICE_MIN_MSAT {
                        return Err(APIError::InvalidAmount(format!(
                            "amt_msat in invoice sending an RGB asset cannot be less than {SDK_INVOICE_MIN_MSAT}"
                        )));
                    }
                    Some((rgb_contract_id, rgb_amount))
                }
                (Some(rgb_contract_id), None) => {
                    if amt_msat < SDK_INVOICE_MIN_MSAT {
                        return Err(APIError::InvalidAmount(format!(
                            "amt_msat in invoice sending an RGB asset cannot be less than {SDK_INVOICE_MIN_MSAT}"
                        )));
                    }
                    if let Some(asset_id) = request.asset_id.as_ref() {
                        let payload_contract_id = ContractId::from_str(asset_id)
                            .map_err(|_| APIError::InvalidAssetID(asset_id.clone()))?;
                        if payload_contract_id != rgb_contract_id {
                            return Err(APIError::InvalidInvoice(s!(
                                "invoice RGB contract ID doesn't match the requested one"
                            )));
                        }
                    }
                    let rgb_amount = request.asset_amount.ok_or(APIError::IncompleteRGBInfo)?;
                    Some((rgb_contract_id, rgb_amount))
                }
                (None, None) => None,
                (None, Some(_)) => {
                    return Err(APIError::InvalidInvoice(s!(
                        "invoice has an RGB amount but not an RGB contract ID"
                    )));
                }
            };

            let secret = payment_secret;
            unlocked_state.add_outbound_payment(
                payment_id,
                PaymentInfo {
                    preimage: None,
                    secret,
                    status: status.into(),
                    amt_msat: Some(amt_msat),
                    created_at,
                    updated_at: created_at,
                    payee_pubkey: invoice.get_payee_pub_key(),
                    expires_at: None,
                },
            )?;
            let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
            if let Some((contract_id, rgb_amount)) = rgb_payment {
                write_rgb_payment_info_file(
                    &PathBuf::from(&state.static_state.ldk_data_dir),
                    &payment_hash,
                    contract_id,
                    rgb_amount,
                    false,
                    false,
                );
            }

            match unlocked_state.channel_manager.pay_for_bolt11_invoice(
                &invoice,
                payment_id,
                Some(amt_msat),
                RouteParametersConfig::default(),
                Retry::Timeout(Duration::from_secs(10)),
            ) {
                Ok(_) => {
                    let payee_pubkey = invoice.recover_payee_pub_key();
                    tracing::info!("EVENT: initiated sending {} msats to {}", amt_msat, payee_pubkey);
                }
                Err(e) => {
                    tracing::error!("ERROR: failed to send payment: {:?}", e);
                    status = HtlcStatus::Failed;
                    unlocked_state.update_outbound_payment_status(payment_id, status.into());
                }
            };

            (payment_id, Some(payment_hash), secret)
        };

    Ok(SendPaymentData {
        payment_id: hex_str(&payment_id.0),
        payment_hash: payment_hash.map(|h| hex_str(&h.0)),
        payment_secret: payment_secret.map(|s| hex_str(&s.0)),
        status,
    })
}

pub(crate) async fn sync(state: Arc<AppState>) -> Result<(), APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();
    unlocked_state.rgb_sync()?;
    Ok(())
}


pub(crate) async fn decode_ln_invoice(
    state: Arc<AppState>,
    invoice: String,
) -> Result<DecodeLnInvoiceData, APIError> {
    let _guard = state.get_unlocked_app_state();
    let invoice =
        Bolt11Invoice::from_str(&invoice).map_err(|e| APIError::InvalidInvoice(e.to_string()))?;

    Ok(DecodeLnInvoiceData {
        amt_msat: invoice.amount_milli_satoshis(),
        expiry_sec: invoice.expiry_time().as_secs(),
        timestamp: invoice.duration_since_epoch().as_secs(),
        asset_id: invoice.rgb_contract_id().map(|c| c.to_string()),
        asset_amount: invoice.rgb_amount(),
        payment_hash: hex_str(&invoice.payment_hash().to_byte_array()),
        payment_secret: hex_str(&invoice.payment_secret().0),
        payee_pubkey: invoice.payee_pub_key().map(|p| p.to_string()),
        network: match invoice.network() {
            bitcoin::Network::Bitcoin => rgb_lib::BitcoinNetwork::Mainnet,
            bitcoin::Network::Testnet => rgb_lib::BitcoinNetwork::Testnet,
            bitcoin::Network::Testnet4 => rgb_lib::BitcoinNetwork::Testnet4,
            bitcoin::Network::Signet => rgb_lib::BitcoinNetwork::Signet,
            bitcoin::Network::Regtest => rgb_lib::BitcoinNetwork::Regtest,
            _ => return Err(APIError::InvalidInvoice("unsupported network".to_string())),
        },
    })
}

pub(crate) async fn decode_rgb_invoice(
    state: Arc<AppState>,
    invoice: String,
) -> Result<DecodeRgbInvoiceData, APIError> {
    let _guard = state.get_unlocked_app_state();
    let invoice_data = RgbLibInvoice::new(invoice)?.invoice_data();
    let recipient_info = RecipientInfo::new(invoice_data.recipient_id.clone())?;

    Ok(DecodeRgbInvoiceData {
        recipient_id: invoice_data.recipient_id,
        recipient_type: recipient_info.recipient_type,
        asset_schema: invoice_data.asset_schema,
        asset_id: invoice_data.asset_id,
        assignment: invoice_data.assignment,
        network: invoice_data.network,
        expiration_timestamp: invoice_data.expiration_timestamp,
        transport_endpoints: invoice_data.transport_endpoints,
    })
}

pub(crate) async fn invoice_status(
    state: Arc<AppState>,
    invoice: String,
) -> Result<InvoiceStatusData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let invoice =
        Bolt11Invoice::from_str(&invoice).map_err(|e| APIError::InvalidInvoice(e.to_string()))?;
    let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
    let status = match unlocked_state.inbound_payments().get(&payment_hash) {
        Some(v) => match HtlcStatus::from(v.status) {
            HtlcStatus::Pending if invoice.is_expired() => InvoiceStatus::Expired,
            HtlcStatus::Pending => InvoiceStatus::Pending,
            HtlcStatus::Succeeded => InvoiceStatus::Succeeded,
            HtlcStatus::Failed => InvoiceStatus::Failed,
        },
        None => return Err(APIError::UnknownLNInvoice),
    };

    Ok(InvoiceStatusData { status })
}

/*
 * -------------------------------------------------------------------------
 * SDK-ONLY ADAPTERS (UniFFI-oriented)
 * -------------------------------------------------------------------------
 * This method is an SDK-facing adapter corresponding to `routes::ln_invoice`.
 * It keeps route-equivalent semantics while using SDK-native parameter shape.
 */
pub(crate) async fn create_ln_invoice(
    state: Arc<AppState>,
    amt_msat: Option<u64>,
    expiry_sec: u32,
    asset_id: Option<String>,
    asset_amount: Option<u64>,
) -> Result<LnInvoiceData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let contract_id = if let Some(asset_id) = asset_id {
        Some(ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?)
    } else {
        None
    };

    if contract_id.is_some() && amt_msat.unwrap_or(0) < SDK_INVOICE_MIN_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "amt_msat cannot be less than {} when transferring an RGB asset",
            SDK_INVOICE_MIN_MSAT
        )));
    }

    let invoice_params = Bolt11InvoiceParameters {
        amount_msats: amt_msat,
        invoice_expiry_delta_secs: Some(expiry_sec),
        contract_id,
        asset_amount,
        ..Default::default()
    };

    let invoice = match unlocked_state
        .channel_manager
        .create_bolt11_invoice(invoice_params)
    {
        Ok(inv) => inv,
        Err(e) => return Err(APIError::FailedInvoiceCreation(e.to_string())),
    };

    let payment_hash = PaymentHash((*invoice.payment_hash()).to_byte_array());
    let created_at = get_current_timestamp();
    unlocked_state.add_inbound_payment(
        payment_hash,
        PaymentInfo {
            preimage: None,
            secret: Some(*invoice.payment_secret()),
            status: HtlcStatus::Pending.into(),
            amt_msat,
            created_at,
            updated_at: created_at,
            payee_pubkey: unlocked_state.channel_manager.get_our_node_id(),
            expires_at: Some(created_at + expiry_sec as u64),
        },
    );

    Ok(LnInvoiceData {
        invoice: invoice.to_string(),
    })
}


pub(crate) async fn list_payments(state: Arc<AppState>) -> Result<Vec<PaymentData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    // Keep inbound invoice status consistent with expiry when payments are read.
    let inbound_payments = unlocked_state.list_updated_inbound_payments();
    let outbound_payments = unlocked_state.outbound_payments();
    let mut payments = vec![];

    for (payment_hash, payment_info) in &inbound_payments {
        let rgb_payment_info_path_inbound =
            get_rgb_payment_info_path(payment_hash, &state.static_state.ldk_data_dir, true);

        let (asset_amount, asset_id) = if rgb_payment_info_path_inbound.exists() {
            let info = parse_rgb_payment_info(&rgb_payment_info_path_inbound);
            (Some(info.amount), Some(info.contract_id.to_string()))
        } else {
            (None, None)
        };

        payments.push(PaymentData {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            inbound: true,
            status: payment_info.status.into(),
            created_at: payment_info.created_at,
            updated_at: payment_info.updated_at,
            payee_pubkey: payment_info.payee_pubkey.to_string(),
        });
    }

    for (payment_id, payment_info) in &outbound_payments {
        let payment_hash = &PaymentHash(payment_id.0);

        let rgb_payment_info_path_outbound =
            get_rgb_payment_info_path(payment_hash, &state.static_state.ldk_data_dir, false);

        let (asset_amount, asset_id) = if rgb_payment_info_path_outbound.exists() {
            let info = parse_rgb_payment_info(&rgb_payment_info_path_outbound);
            (Some(info.amount), Some(info.contract_id.to_string()))
        } else {
            (None, None)
        };

        payments.push(PaymentData {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            inbound: false,
            status: payment_info.status.into(),
            created_at: payment_info.created_at,
            updated_at: payment_info.updated_at,
            payee_pubkey: payment_info.payee_pubkey.to_string(),
        });
    }

    Ok(payments)
}

pub(crate) async fn get_payment(
    state: Arc<AppState>,
    payment_hash_hex: String,
) -> Result<PaymentData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash_vec = hex_str_to_vec(&payment_hash_hex);
    if payment_hash_vec.is_none() || payment_hash_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentHash(payment_hash_hex));
    }
    let requested_ph = PaymentHash(payment_hash_vec.unwrap().try_into().unwrap());

    // Keep inbound invoice status consistent with expiry when a specific payment is read.
    let inbound_payments = unlocked_state.list_updated_inbound_payments();
    let outbound_payments = unlocked_state.outbound_payments();

    for (payment_hash, payment_info) in &inbound_payments {
        if payment_hash == &requested_ph {
            let rgb_payment_info_path_inbound =
                get_rgb_payment_info_path(payment_hash, &state.static_state.ldk_data_dir, true);

            let (asset_amount, asset_id) = if rgb_payment_info_path_inbound.exists() {
                let info = parse_rgb_payment_info(&rgb_payment_info_path_inbound);
                (Some(info.amount), Some(info.contract_id.to_string()))
            } else {
                (None, None)
            };

            return Ok(PaymentData {
                amt_msat: payment_info.amt_msat,
                asset_amount,
                asset_id,
                payment_hash: hex_str(&payment_hash.0),
                inbound: true,
                status: payment_info.status.into(),
                created_at: payment_info.created_at,
                updated_at: payment_info.updated_at,
                payee_pubkey: payment_info.payee_pubkey.to_string(),
            });
        }
    }

    for (payment_id, payment_info) in &outbound_payments {
        let payment_hash = &PaymentHash(payment_id.0);
        if payment_hash == &requested_ph {
            let rgb_payment_info_path_outbound =
                get_rgb_payment_info_path(payment_hash, &state.static_state.ldk_data_dir, false);

            let (asset_amount, asset_id) = if rgb_payment_info_path_outbound.exists() {
                let info = parse_rgb_payment_info(&rgb_payment_info_path_outbound);
                (Some(info.amount), Some(info.contract_id.to_string()))
            } else {
                (None, None)
            };

            return Ok(PaymentData {
                amt_msat: payment_info.amt_msat,
                asset_amount,
                asset_id,
                payment_hash: hex_str(&payment_hash.0),
                inbound: false,
                status: payment_info.status.into(),
                created_at: payment_info.created_at,
                updated_at: payment_info.updated_at,
                payee_pubkey: payment_info.payee_pubkey.to_string(),
            });
        }
    }

    Err(APIError::PaymentNotFound(payment_hash_hex))
}


fn map_swap(
    payment_hash: &PaymentHash,
    swap_data: &SwapData,
    taker: bool,
    state: &crate::utils::UnlockedAppState,
) -> SwapViewData {
    let mut status: SwapStatus = swap_data.status.into();
    if status == SwapStatus::Waiting && get_current_timestamp() > swap_data.swap_info.expiry {
        status = SwapStatus::Expired;
    } else if status == SwapStatus::Pending
        && get_current_timestamp() > swap_data.initiated_at.unwrap() + 86400
    {
        status = SwapStatus::Failed;
    }
    let current_status: SwapStatus = swap_data.status.into();
    if status != current_status {
        if taker {
            state.update_taker_swap_status(payment_hash, status.into());
        } else {
            state.update_maker_swap_status(payment_hash, status.into());
        }
    }

    SwapViewData {
        payment_hash: payment_hash.to_string(),
        qty_from: swap_data.swap_info.qty_from,
        qty_to: swap_data.swap_info.qty_to,
        from_asset: swap_data.swap_info.from_asset.map(|c| c.to_string()),
        to_asset: swap_data.swap_info.to_asset.map(|c| c.to_string()),
        status,
        requested_at: swap_data.requested_at,
        initiated_at: swap_data.initiated_at,
        expires_at: swap_data.swap_info.expiry,
        completed_at: swap_data.completed_at,
    }
}

pub(crate) async fn get_swap(
    state: Arc<AppState>,
    payment_hash_hex: String,
    taker: bool,
) -> Result<SwapViewData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash_vec = hex_str_to_vec(&payment_hash_hex);
    if payment_hash_vec.is_none() || payment_hash_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentHash(payment_hash_hex));
    }
    let requested_ph = PaymentHash(payment_hash_vec.unwrap().try_into().unwrap());

    if taker {
        let taker_swaps = unlocked_state.taker_swaps();
        if let Some(sd) = taker_swaps.get(&requested_ph) {
            return Ok(map_swap(&requested_ph, sd, true, unlocked_state));
        }
    } else {
        let maker_swaps = unlocked_state.maker_swaps();
        if let Some(sd) = maker_swaps.get(&requested_ph) {
            return Ok(map_swap(&requested_ph, sd, false, unlocked_state));
        }
    }

    Err(APIError::SwapNotFound(payment_hash_hex))
}

pub(crate) async fn list_swaps(state: Arc<AppState>) -> Result<SwapListData, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let taker_swaps = unlocked_state.taker_swaps();
    let maker_swaps = unlocked_state.maker_swaps();

    Ok(SwapListData {
        taker: taker_swaps
            .iter()
            .map(|(ph, sd)| map_swap(ph, sd, true, unlocked_state))
            .collect(),
        maker: maker_swaps
            .iter()
            .map(|(ph, sd)| map_swap(ph, sd, false, unlocked_state))
            .collect(),
    })
}


pub(crate) async fn list_transactions(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<Vec<TransactionData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut transactions = vec![];
    for tx in unlocked_state.rgb_list_transactions(skip_sync)? {
        transactions.push(TransactionData {
            transaction_type: match tx.transaction_type {
                rgb_lib::TransactionType::RgbSend => TransactionType::RgbSend,
                rgb_lib::TransactionType::Drain => TransactionType::Drain,
                rgb_lib::TransactionType::CreateUtxos => TransactionType::CreateUtxos,
                rgb_lib::TransactionType::User => TransactionType::User,
            },
            txid: tx.txid,
            received: tx.received,
            sent: tx.sent,
            fee: tx.fee,
            confirmation_time: tx.confirmation_time.map(|ct| BlockTime {
                height: ct.height,
                timestamp: ct.timestamp,
            }),
        });
    }

    Ok(transactions)
}

pub(crate) async fn list_transfers(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<Vec<TransferData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut transfers = vec![];
    for transfer in unlocked_state.rgb_list_transfers(asset_id)? {
        transfers.push(TransferData {
            idx: transfer.idx,
            created_at: transfer.created_at,
            updated_at: transfer.updated_at,
            status: match transfer.status {
                rgb_lib::TransferStatus::WaitingCounterparty => TransferStatus::WaitingCounterparty,
                rgb_lib::TransferStatus::WaitingConfirmations => {
                    TransferStatus::WaitingConfirmations
                }
                rgb_lib::TransferStatus::Settled => TransferStatus::Settled,
                rgb_lib::TransferStatus::Failed => TransferStatus::Failed,
            },
            requested_assignment: transfer.requested_assignment,
            assignments: transfer.assignments,
            kind: match transfer.kind {
                rgb_lib::TransferKind::Issuance => TransferKind::Issuance,
                rgb_lib::TransferKind::ReceiveBlind => TransferKind::ReceiveBlind,
                rgb_lib::TransferKind::ReceiveWitness => TransferKind::ReceiveWitness,
                rgb_lib::TransferKind::Send => TransferKind::Send,
                rgb_lib::TransferKind::Inflation => TransferKind::Inflation,
            },
            txid: transfer.txid,
            recipient_id: transfer.recipient_id,
            receive_utxo: transfer.receive_utxo.map(|u| u.to_string()),
            change_utxo: transfer.change_utxo.map(|u| u.to_string()),
            expiration: transfer.expiration,
            transport_endpoints: transfer
                .transport_endpoints
                .iter()
                .map(|tte| TransferTransportEndpointData {
                    endpoint: tte.endpoint.clone(),
                    transport_type: match tte.transport_type {
                        rgb_lib::TransportType::JsonRpc => TransportType::JsonRpc,
                    },
                    used: tte.used,
                })
                .collect(),
        });
    }
    Ok(transfers)
}

pub(crate) async fn list_unspents(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<Vec<UnspentData>, APIError> {
    let guard = state.check_unlocked().await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut unspents = vec![];
    for unspent in unlocked_state.rgb_list_unspents(skip_sync)? {
        unspents.push(UnspentData {
            utxo: UtxoData {
                outpoint: unspent.utxo.outpoint.to_string(),
                btc_amount: unspent.utxo.btc_amount,
                colorable: unspent.utxo.colorable,
            },
            rgb_allocations: unspent
                .rgb_allocations
                .iter()
                .map(|a| RgbAllocationData {
                    asset_id: a.asset_id.clone(),
                    assignment: a.assignment.clone(),
                    settled: a.settled,
                })
                .collect(),
        });
    }
    Ok(unspents)
}
