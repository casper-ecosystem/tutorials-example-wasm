#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

extern crate alloc;
use alloc::string::ToString;
use casper_contract::contract_api::{runtime, storage};
use casper_contract::unwrap_or_revert::UnwrapOrRevert;
use casper_types::{AccessRights, ApiError, ContractHash, URef};

const CONTRACT_HASH: &str = "contract_hash";
const MY_STORED_VALUE_UREF: &str = "my_stored_value_uref";
const ARG_MY_STORED_VALUE: &str = "my_stored_value";

#[repr(u16)]
enum UserError {
    StoredValueError = 0,
}

impl From<UserError> for ApiError {
    fn from(user_error: UserError) -> Self {
        ApiError::User(user_error as u16)
    }
}

#[no_mangle]
pub extern "C" fn call() {
    let _contract_hash: ContractHash = runtime::get_key(CONTRACT_HASH)
        .unwrap_or_revert()
        .into_hash()
        .map(ContractHash::new)
        .unwrap_or_revert();

    let my_stored_value_uref: URef = runtime::get_key(MY_STORED_VALUE_UREF)
        .unwrap_or_revert()
        .into_uref()
        .map(|uref| URef::new(uref.addr(), AccessRights::default()))
        .unwrap_or_revert()
        .into_read();

    let my_actual_stored_value: bool = storage::read(my_stored_value_uref).unwrap().unwrap();

    // Compare my stored value with runtime arg
    let my_expected_stored_value: bool = runtime::get_named_arg(ARG_MY_STORED_VALUE);
    if my_actual_stored_value != my_expected_stored_value {
        // We revert if my stored value is not what is expected from caller argument
        runtime::revert(UserError::StoredValueError);
    }

    runtime::print(&my_actual_stored_value.to_string());
}
