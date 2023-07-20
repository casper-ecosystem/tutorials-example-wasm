#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

use casper_contract::contract_api::{account, runtime};
use casper_contract::unwrap_or_revert::UnwrapOrRevert;
use casper_types::account::{ActionType, Weight};
use update_thresholds::constants::{
    RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD, RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD,
};

#[no_mangle]
pub extern "C" fn call() {
    let deployment_threshold: u8 = runtime::get_named_arg(RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD);
    let key_mgmt_threshold: u8 = runtime::get_named_arg(RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD);

    account::set_action_threshold(ActionType::KeyManagement, Weight::new(key_mgmt_threshold))
        .unwrap_or_revert();
    account::set_action_threshold(ActionType::Deployment, Weight::new(deployment_threshold))
        .unwrap_or_revert();
}
