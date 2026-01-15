use super::*;
use crate::error::APIError;
use crate::utils::{check_already_initialized, check_password_validity, encrypt_and_save_mnemonic};
use sea_orm::{Database, DatabaseConnection};
use tempfile::TempDir;

#[traced_test]
#[tokio::test]
async fn test_encrypt_and_save_mnemonic() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    let db: DatabaseConnection = Database::connect(&db_url).await.unwrap();

    let password = "test_password_123";
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let result = encrypt_and_save_mnemonic(password.to_string(), mnemonic.to_string(), &db).await;
    assert!(
        result.is_ok(),
        "Failed to encrypt and save mnemonic: {:?}",
        result
    );

    let retrieved_mnemonic = check_password_validity(password, &db).await;
    assert!(
        retrieved_mnemonic.is_ok(),
        "Failed to retrieve mnemonic: {:?}",
        retrieved_mnemonic
    );
    assert_eq!(retrieved_mnemonic.unwrap().to_string(), mnemonic);
}

#[traced_test]
#[tokio::test]
async fn test_check_password_validity_wrong_password() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    let db: DatabaseConnection = Database::connect(&db_url).await.unwrap();

    let password = "correct_password";
    let wrong_password = "wrong_password";
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    encrypt_and_save_mnemonic(password.to_string(), mnemonic.to_string(), &db)
        .await
        .unwrap();

    let result = check_password_validity(wrong_password, &db).await;
    assert!(
        matches!(result, Err(APIError::WrongPassword)),
        "Expected WrongPassword error, got {:?}",
        result
    );
}

#[traced_test]
#[tokio::test]
async fn test_check_password_validity_uninitialized() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    let db: DatabaseConnection = Database::connect(&db_url).await.unwrap();

    let password = "some_password";

    let result = check_password_validity(password, &db).await;
    assert!(
        matches!(result, Err(APIError::NotInitialized)),
        "Expected NotInitialized error, got {:?}",
        result
    );
}

#[traced_test]
#[tokio::test]
async fn test_check_already_initialized() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    let db: DatabaseConnection = Database::connect(&db_url).await.unwrap();

    let result = check_already_initialized(&db).await;
    assert!(
        result.is_ok(),
        "Expected OK for uninitialized, got {:?}",
        result
    );

    let password = "test_password";
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    encrypt_and_save_mnemonic(password.to_string(), mnemonic.to_string(), &db)
        .await
        .unwrap();

    let result = check_already_initialized(&db).await;
    assert!(
        matches!(result, Err(APIError::AlreadyInitialized)),
        "Expected AlreadyInitialized error, got {:?}",
        result
    );
}
