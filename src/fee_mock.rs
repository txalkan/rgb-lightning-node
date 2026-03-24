#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
lazy_static::lazy_static! {
    static ref MOCK_FEE: Mutex<Option<u32>> = Mutex::new(None);
}

#[cfg(test)]
pub(crate) fn mock_fee(fee: u32) -> u32 {
    let mock = MOCK_FEE.lock().unwrap().take();
    if let Some(fee) = mock {
        println!("mocking fee");
        fee
    } else {
        fee
    }
}

#[cfg(test)]
pub(crate) fn set_mock_fee_for_tests(fee: Option<u32>) {
    *MOCK_FEE.lock().unwrap() = fee;
}
