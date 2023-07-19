#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

use casper_contract::contract_api::{account, runtime};
use casper_contract::unwrap_or_revert::UnwrapOrRevert;
use casper_types::account::Weight;
use casper_types::Key;
use update_associated_keys::constants::{RUNTIME_ARG_ASSOCIATED_KEY, RUNTIME_ARG_NEW_KEY_WEIGHT};
use update_associated_keys::errors::UserError;

#[no_mangle]
pub extern "C" fn call() {
    let associated_account: Key = runtime::get_named_arg(RUNTIME_ARG_ASSOCIATED_KEY);
    if let Key::Account(account) = associated_account {
        let new_weight: u8 = runtime::get_named_arg(RUNTIME_ARG_NEW_KEY_WEIGHT);
        account::update_associated_key(account, Weight::new(new_weight)).unwrap_or_revert();
    } else {
        runtime::revert(UserError::InvalidAccount);
    }
}
