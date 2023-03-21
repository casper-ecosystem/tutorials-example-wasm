#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

mod constants;
extern crate alloc;

use alloc::string::ToString;
use casper_contract::contract_api::{runtime, storage};

use casper_types::{EntryPoints, Key};
use constants::{
    ACCESS_KEY, CONTRACT_HASH, CONTRACT_PACKAGE, MY_STORED_VALUE, MY_STORED_VALUE_UREF,
};

#[no_mangle]
pub extern "C" fn call() {
    let (contract_hash, _version) = storage::new_contract(
        EntryPoints::new(),
        None,
        Some(CONTRACT_PACKAGE.to_string()),
        Some(ACCESS_KEY.to_string()),
    );

    // Store contract hash under a Named key CONTRACT_HASH
    runtime::put_key(CONTRACT_HASH, contract_hash.into());

    // Store !MY_STORED_VALUE (false) as init value/type into a new URef
    let my_value_uref = storage::new_uref(!MY_STORED_VALUE);

    // Store MY_STORED_VALUE (true) under the URef value
    storage::write(my_value_uref, MY_STORED_VALUE);

    // Store the Uref under a Named key MY_STORED_VALUE_UREF
    let my_value_key: Key = my_value_uref.into();
    runtime::put_key(MY_STORED_VALUE_UREF, my_value_key);
}
