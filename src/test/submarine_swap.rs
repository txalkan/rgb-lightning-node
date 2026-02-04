use super::*;
use crate::ldk::{HtlcTrackerStorage, HtlcUtxoKind};
use crate::routes::HtlcClaimRequest;
use bitcoin::{Address, Network, ScriptBuf};
use lightning::util::ser::Readable;
use std::path::Path;

const TEST_DIR_BASE: &str = "tmp/submarine_swap/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_invoice_htlc_binds_to_p2tr_script() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}happy_path/");
    let (node1_addr, test_dir_node1) =
        setup_single_node(&test_dir_base, "node1", NODE1_PEER_PORT).await;
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let keypair = SecpKeyPair::new(&secp, &mut rng);
    let user_pubkey = bitcoin::PublicKey::new(keypair.public_key());

    let (_, payment_hash_hex) = random_preimage_and_hash();

    let current_height = get_block_count();
    let csv = 210;
    let response = rgb_invoice_htlc(
        node1_addr,
        Some(asset_id.clone()),
        Some(Assignment::Fungible(42)),
        Some(3600),
        payment_hash_hex.clone(),
        user_pubkey.to_string(),
        csv,
    )
    .await;

    println!("rgbinvoicehtlc response: {}", response.invoice);

    assert_eq!(response.batch_transfer_idx, 0);
    assert!(response.expiration_timestamp.is_some());

    let decoded = decode_rgb_invoice(node1_addr, &response.invoice).await;
    assert_eq!(decoded.recipient_type, RecipientType::Witness);
    assert_eq!(decoded.network, ApiBitcoinNetwork::Regtest);
    assert_eq!(decoded.asset_id.as_deref(), Some(asset_id.as_str()));
    assert_eq!(decoded.assignment, Assignment::Fungible(42));
    assert_eq!(decoded.transport_endpoints, vec![PROXY_ENDPOINT_LOCAL]);

    let tracker_path = Path::new(&test_dir_node1).join(LDK_DIR);
    let tracker = read_htlc_tracker(tracker_path.as_path());
    let payment_hash =
        validate_and_parse_payment_hash(payment_hash_hex.as_str()).expect("payment_hash parse");
    let entry = tracker
        .entries
        .get(&payment_hash)
        .expect("htlc tracker entry");
    assert_eq!(entry.status, "Created");
    assert_eq!(entry.recipient_id, response.recipient_id);
    assert_eq!(entry.rgb_invoice, response.invoice);
    assert_eq!(entry.htlc_script_pubkey, response.htlc_p2tr_script_pubkey);
    assert_eq!(entry.t_lock, current_height + csv);
    assert_eq!(entry.min_confirmations, 1);
    assert!(entry.preimage.is_none());
    assert!(entry.funding.is_empty());
    assert!(entry.claim_tapscript_hex.is_some());
    assert!(entry.refund_tapscript_hex.is_some());
    assert!(entry.tapleaf_version.is_some());
    assert!(entry.control_block_hex.is_some());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_invoice_htlc_rejects_invalid_params() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}invalid_params/");
    let (node1_addr, _test_dir_node1) =
        setup_single_node(&test_dir_base, "node1", NODE1_PEER_PORT).await;

    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let keypair = SecpKeyPair::new(&secp, &mut rng);
    let user_pubkey = bitcoin::PublicKey::new(keypair.public_key());

    let short_payload = RgbInvoiceHtlcRequest {
        asset_id: None,
        assignment: None,
        duration_seconds: Some(0),
        min_confirmations: 1,
        payment_hash: "51".to_string(),
        user_pubkey: user_pubkey.to_string(),
        csv: 100,
    };
    post_and_check_error_response(
        node1_addr,
        "/rgbinvoicehtlc",
        &short_payload,
        StatusCode::BAD_REQUEST,
        "Invalid payment hash",
        "InvalidPaymentHash",
    )
    .await;

    let (_, payment_hash_hex) = random_preimage_and_hash();

    let bad_prefix_payload = RgbInvoiceHtlcRequest {
        asset_id: None,
        assignment: None,
        duration_seconds: Some(0),
        min_confirmations: 1,
        payment_hash: payment_hash_hex,
        user_pubkey: "02".to_string(),
        csv: 100,
    };
    post_and_check_error_response(
        node1_addr,
        "/rgbinvoicehtlc",
        &bad_prefix_payload,
        StatusCode::BAD_REQUEST,
        "Invalid user compressed pubkey",
        "InvalidHtlcParams",
    )
    .await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn htlc_claim_updates_tracker_for_vanilla_utxo() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}htlc_claim/");
    let (node1_addr, test_dir_node1) =
        setup_single_node(&test_dir_base, "node1", NODE1_PEER_PORT).await;
    let test_dir_node1 = Path::new(&test_dir_node1);

    let (preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let keypair = SecpKeyPair::new(&secp, &mut rng);
    let user_pubkey = bitcoin::PublicKey::new(keypair.public_key());

    let response = rgb_invoice_htlc(
        node1_addr,
        None,
        None,
        Some(3600),
        payment_hash_hex.clone(),
        user_pubkey.to_string(),
        210,
    )
    .await;

    let htlc_spk_hex = response.htlc_p2tr_script_pubkey.as_str();
    let script_bytes = hex_str_to_vec(htlc_spk_hex).expect("htlc_p2tr_script_pubkey hex");
    let script_buf = ScriptBuf::from_bytes(script_bytes);
    let htlc_address = Address::from_script(&script_buf, Network::Regtest).expect("htlc address");

    _fund_wallet(htlc_address.to_string());
    mine(false);

    let payload = HtlcClaimRequest {
        payment_hash: payment_hash_hex.clone(),
        preimage: preimage_hex.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/htlcclaim"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res).await;

    let tracker_path = test_dir_node1.join(LDK_DIR);
    assert!(
        tracker_path.join("htlc_tracker.json").exists(),
        "htlc tracker file missing at {}",
        tracker_path.display()
    );
    let tracker_file =
        std::fs::File::open(tracker_path.join("htlc_tracker.json")).expect("open htlc tracker");
    let tracker = HtlcTrackerStorage::read(&mut std::io::BufReader::new(tracker_file))
        .expect("decode htlc tracker");
    assert!(
        !tracker.entries.is_empty(),
        "htlc tracker empty at {}",
        tracker_path.display()
    );
    let entry = tracker
        .entries
        .iter()
        .find(|(k, _)| hex_str(&k.0).eq_ignore_ascii_case(&payment_hash_hex))
        .map(|(_, v)| v)
        .expect("htlc tracker entry");
    assert_eq!(entry.status, "ClaimRequested");
    assert_eq!(entry.funding.len(), 1);
    assert_eq!(entry.funding[0].utxo_kind(), HtlcUtxoKind::Vanilla);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn htlc_claim_updates_tracker_for_colored_utxo() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}htlc_claim_colored/");
    let (node1_addr, test_dir_node1) =
        setup_single_node(&test_dir_base, "node1", NODE1_PEER_PORT).await;
    let test_dir_node1 = Path::new(&test_dir_node1);

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let (preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let keypair = SecpKeyPair::new(&secp, &mut rng);
    let user_pubkey = bitcoin::PublicKey::new(keypair.public_key());

    let response = rgb_invoice_htlc(
        node1_addr,
        Some(asset_id.clone()),
        Some(Assignment::Fungible(42)),
        Some(3600),
        payment_hash_hex.clone(),
        user_pubkey.to_string(),
        210,
    )
    .await;

    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(42),
        response.recipient_id.clone(),
        Some(WitnessData {
            amount_sat: 1000,
            blinding: None,
        }),
    )
    .await;
    mine(false);
    refresh_transfers(node1_addr).await;

    let payload = HtlcClaimRequest {
        payment_hash: payment_hash_hex.clone(),
        preimage: preimage_hex.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/htlcclaim"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res).await;

    let tracker_path = test_dir_node1.join(LDK_DIR);
    let tracker_file =
        std::fs::File::open(tracker_path.join("htlc_tracker.json")).expect("open htlc tracker");
    let tracker = HtlcTrackerStorage::read(&mut std::io::BufReader::new(tracker_file))
        .expect("decode htlc tracker");
    let entry = tracker
        .entries
        .iter()
        .find(|(k, _)| hex_str(&k.0).eq_ignore_ascii_case(&payment_hash_hex))
        .map(|(_, v)| v)
        .expect("htlc tracker entry");
    assert_eq!(entry.status, "ClaimRequested");
    assert_eq!(entry.funding.len(), 1);
    assert_eq!(entry.funding[0].utxo_kind(), HtlcUtxoKind::Colored);
    assert_eq!(
        entry.funding[0].assignment(),
        Some(Assignment::Fungible(42))
    );
}
