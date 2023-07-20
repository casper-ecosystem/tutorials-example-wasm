use casper_types::account::AccountHash;

pub const ADD_ACCOUNT_WASM: &str = "add_account.wasm";
pub const REMOVE_ACCOUNT_WASM: &str = "remove_account.wasm";
pub const UPDATE_KEYS_WASM: &str = "update_associated_keys.wasm";
pub const UPDATE_THRESHOLDS_WASM: &str = "update_thresholds.wasm";
pub const CONTRACT_WASM: &str = "contract.wasm";

pub const TEST_VALUE: &str = "hello world";
pub const KEY_NAME: &str = "my-key-name";
pub const RUNTIME_ARG_NAME: &str = "message";

pub const USER_1_ACCOUNT: AccountHash = AccountHash::new([1u8; 32]);
pub const USER_2_ACCOUNT: AccountHash = AccountHash::new([2u8; 32]);
