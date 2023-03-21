#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

extern crate alloc;
use alloc::{string::String, vec::Vec};

use casper_contract::contract_api::{runtime, storage};
use casper_types::{account::AccountHash, runtime_args, ContractHash, Key, RuntimeArgs};

const ENTRY_POINT: &str = "entrypoint";
const ARG_CONTRACT_HASH: &str = "contract_hash";
const ARG_KEY_NAME: &str = "key_name";

#[no_mangle]
pub extern "C" fn call() {
    let contract_hash: ContractHash = runtime::get_named_arg::<Key>(ARG_CONTRACT_HASH)
        .into_hash()
        .map(|hash| ContractHash::new(hash))
        .unwrap();

    let key_name: String = runtime::get_named_arg(ARG_KEY_NAME);
    let intersection =
        runtime::call_contract::<Vec<AccountHash>>(contract_hash, ENTRY_POINT, runtime_args! {});
    runtime::put_key(&key_name, storage::new_uref(intersection).into());
}
