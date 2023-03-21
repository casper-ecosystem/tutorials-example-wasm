#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

mod constants;
extern crate alloc;

use core::convert::TryInto;

use alloc::{string::ToString, vec, vec::Vec};
use casper_contract::{
    contract_api::{runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    account::AccountHash, contracts::Parameters, runtime_args, ApiError, CLType, CLValue,
    EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, Key, RuntimeArgs,
};
use constants::{
    ACCESS_KEY, AUTHORIZATION_KEYS_INSTALLER, CONTRACT_HASH, CONTRACT_PACKAGE, ENTRYPOINT, INIT,
};

#[repr(u16)]
enum UserError {
    PermissionDenied = 0,
    FailedToConvertToCLValue = 1,
}

impl From<UserError> for ApiError {
    fn from(user_error: UserError) -> Self {
        ApiError::User(user_error as u16)
    }
}

fn key_intersect(v1: &[AccountHash], v2: &[AccountHash]) -> Vec<AccountHash> {
    v1.iter().filter(|&x| v2.contains(x)).cloned().collect()
}

#[no_mangle]
pub extern "C" fn entrypoint() {
    let authorization_keys_installer: Vec<AccountHash> =
        runtime::get_key(AUTHORIZATION_KEYS_INSTALLER)
            .map(|key| {
                let key = key.try_into().unwrap_or_revert();
                storage::read(key).unwrap_or_revert().unwrap_or_revert()
            })
            .unwrap_or_revert();

    let authorization_keys_caller: Vec<AccountHash> =
        runtime::list_authorization_keys().iter().cloned().collect();

    runtime::print("authorization_keys of installer");
    for key in authorization_keys_installer.iter() {
        runtime::print(&key.to_formatted_string());
    }
    runtime::print("authorization_keys of caller");
    for key in authorization_keys_caller.iter() {
        runtime::print(&key.to_formatted_string());
    }

    let intersection = key_intersect(&authorization_keys_installer, &authorization_keys_caller);

    if intersection.is_empty() {
        // None of the authorization keys used to sign this deploy was in contract installer authorization keys
        runtime::revert(UserError::PermissionDenied)
    }

    let intersection_cl_value =
        CLValue::from_t(intersection).unwrap_or_revert_with(UserError::FailedToConvertToCLValue);
    runtime::ret(intersection_cl_value);
}

#[no_mangle]
pub extern "C" fn init() {
    if runtime::get_key(AUTHORIZATION_KEYS_INSTALLER).is_none() {
        let authorization_keys: Vec<AccountHash> =
            runtime::list_authorization_keys().iter().cloned().collect();

        let authorization_keys: Key = storage::new_uref(authorization_keys).into();
        runtime::put_key(AUTHORIZATION_KEYS_INSTALLER, authorization_keys);
    }
}

#[no_mangle]
pub extern "C" fn call() {
    let entry_points = {
        let mut entry_points = EntryPoints::new();

        let entrypoint = EntryPoint::new(
            ENTRYPOINT,
            Parameters::default(),
            CLType::Unit,
            EntryPointAccess::Public,
            EntryPointType::Contract,
        );
        entry_points.add_entry_point(entrypoint);

        let entrypoint = EntryPoint::new(
            INIT,
            vec![],
            CLType::Unit,
            EntryPointAccess::Public,
            EntryPointType::Contract,
        );

        entry_points.add_entry_point(entrypoint);
        entry_points
    };

    let (contract_hash, _version) = storage::new_contract(
        entry_points,
        None,
        Some(CONTRACT_PACKAGE.to_string()),
        Some(ACCESS_KEY.to_string()),
    );

    // Calls INIT entry point of the new contract
    runtime::call_contract::<()>(contract_hash, INIT, runtime_args! {});

    runtime::put_key(CONTRACT_HASH, contract_hash.into());
}
