use super::*;

const TEST_DIR_BASE: &str = "tmp/submarine_rgb/";

fn build_p2tr_script_hex() -> (String, ScriptBuf) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let keypair = SecpKeyPair::new(&secp, &mut rng);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

    let mut script_bytes = Vec::with_capacity(34);
    script_bytes.push(0x51);
    script_bytes.push(0x20);
    script_bytes.extend_from_slice(&xonly.serialize());

    let script = ScriptBuf::from_bytes(script_bytes.clone());
    (hex_str(&script_bytes), script)
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_invoice_htlc_binds_to_p2tr_script() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}happy_path/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let (script_hex, script_buf) = build_p2tr_script_hex();
    let expected_recipient = recipient_id_from_script_buf(script_buf, BitcoinNetwork::Regtest);

    let response = rgb_invoice_htlc(
        node1_addr,
        Some(asset_id.clone()),
        Some(Assignment::Fungible(42)),
        Some(3600),
        script_hex,
        210_000,
    )
    .await;

    println!("rgbinvoicehtlc response: {}", response.invoice);

    assert_eq!(response.recipient_id, expected_recipient);
    assert_eq!(response.batch_transfer_idx, 0);
    assert!(response.expiration_timestamp.is_some());

    let decoded = decode_rgb_invoice(node1_addr, &response.invoice).await;
    assert_eq!(decoded.recipient_id, expected_recipient);
    assert_eq!(decoded.recipient_type, RecipientType::Witness);
    assert_eq!(decoded.network, ApiBitcoinNetwork::Regtest);
    assert_eq!(decoded.asset_id.as_deref(), Some(asset_id.as_str()));
    assert_eq!(decoded.assignment, Assignment::Fungible(42));
    assert_eq!(decoded.transport_endpoints, vec![PROXY_ENDPOINT_LOCAL]);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_invoice_htlc_rejects_invalid_script() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}invalid_script/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let short_payload = RgbInvoiceHtlcRequest {
        asset_id: None,
        assignment: None,
        duration_seconds: Some(0),
        min_confirmations: 1,
        htlc_p2tr_script_pubkey: "51".to_string(),
        t_lock: 100,
    };
    post_and_check_error_response(
        node1_addr,
        "/rgbinvoicehtlc",
        &short_payload,
        StatusCode::BAD_REQUEST,
        "expected 34 bytes",
        "InvalidRecipientData",
    )
    .await;

    let mut bad_prefix_bytes = Vec::with_capacity(34);
    bad_prefix_bytes.push(0x00);
    bad_prefix_bytes.push(0x20);
    bad_prefix_bytes.extend_from_slice(&[0u8; 32]);
    let bad_prefix_hex = hex_str(&bad_prefix_bytes);

    let bad_prefix_payload = RgbInvoiceHtlcRequest {
        asset_id: None,
        assignment: None,
        duration_seconds: Some(0),
        min_confirmations: 1,
        htlc_p2tr_script_pubkey: bad_prefix_hex,
        t_lock: 100,
    };
    post_and_check_error_response(
        node1_addr,
        "/rgbinvoicehtlc",
        &bad_prefix_payload,
        StatusCode::BAD_REQUEST,
        "prefix: expected OP_1",
        "InvalidRecipientData",
    )
    .await;
}
