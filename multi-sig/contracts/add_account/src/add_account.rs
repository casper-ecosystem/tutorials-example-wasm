#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

use add_account::constants::{
    RUNTIME_ARG_NEW_ASSOCIATED_KEY, RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT,
};
use add_account::errors::UserError;
use casper_contract::contract_api::{account, runtime};
use casper_contract::unwrap_or_revert::UnwrapOrRevert;
use casper_types::account::Weight;
use casper_types::Key;

#[no_mangle]
pub extern "C" fn call() {
    let new_associated_key: Key = runtime::get_named_arg(RUNTIME_ARG_NEW_ASSOCIATED_KEY);

    if let Key::Account(account) = new_associated_key {
        let new_key_weight: u8 = runtime::get_named_arg(RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT);

        account::add_associated_key(account, Weight::new(new_key_weight)).unwrap_or_revert();
    } else {
        runtime::revert(UserError::InvalidAccount);
    }
}
