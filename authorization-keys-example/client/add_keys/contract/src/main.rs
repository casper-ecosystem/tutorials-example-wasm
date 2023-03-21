#![no_std]
#![no_main]

use casper_contract::contract_api::{account, runtime};
use casper_contract::unwrap_or_revert::UnwrapOrRevert;
use casper_types::account::{AccountHash, ActionType, Weight};

const ASSOCIATED_ACCOUNT: &str = "deployment-account";

#[no_mangle]
pub extern "C" fn call() {
    // Account hash for the account to be associated.
    let deployment_account: AccountHash = runtime::get_named_arg(ASSOCIATED_ACCOUNT);

    // Add the CA key to half the deployment threshold (i.e 1)
    account::add_associated_key(deployment_account, Weight::new(1)).unwrap_or_revert();

    // Deployment threshold <= Key management threshold.
    // Therefore update the key management threshold value.
    account::set_action_threshold(ActionType::KeyManagement, Weight::new(2)).unwrap_or_revert();

    // Set the deployment threshold to 2 enforcing multisig to send deploys.
    account::set_action_threshold(ActionType::Deployment, Weight::new(2)).unwrap_or_revert();
}
