use std::path::PathBuf;

use casper_engine_test_support::{
    DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, ARG_AMOUNT,
    DEFAULT_ACCOUNT_ADDR, DEFAULT_PAYMENT, PRODUCTION_RUN_GENESIS_REQUEST,
};

use casper_types::{runtime_args, Key, RuntimeArgs};

use crate::constants::{
    ARG_MY_STORED_VALUE, CONTRACT_HASH, CONTRACT_WASM, MY_STORED_VALUE, MY_STORED_VALUE_UREF,
    NAMED_KEY_SESSION_WASM,
};

#[test]
fn should_allow_install_contract_and_store_named_keys() {
    let mut builder = InMemoryWasmTestBuilder::default();
    builder
        .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
        .commit();

    let session_code = PathBuf::from(CONTRACT_WASM);
    let session_args = RuntimeArgs::new();

    let deploy_item = DeployItemBuilder::new()
        .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
        .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
        .with_address(*DEFAULT_ACCOUNT_ADDR)
        .with_session_code(session_code, session_args)
        .build();

    let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
    builder.exec(execute_request).commit().expect_success();

    let account = builder.get_expected_account(*DEFAULT_ACCOUNT_ADDR);
    account
        .named_keys()
        .get(CONTRACT_HASH)
        .expect("must have this entry in named keys")
        .into_hash()
        .expect("failed to find contract hash");

    // Check if Uref exists in named keys
    account
        .named_keys()
        .get(MY_STORED_VALUE_UREF)
        .expect("must have this entry in named keys")
        .into_uref()
        .expect("failed to find uref");

    // Get value under the named key
    let actual_value = builder
        .query(
            None,
            Key::Account(*DEFAULT_ACCOUNT_ADDR),
            &[MY_STORED_VALUE_UREF.into()],
        )
        .expect("must have stored value")
        .as_cl_value()
        .cloned()
        .expect("must have cl value")
        .into_t::<bool>()
        .expect("must get boolean value");

    assert_eq!(MY_STORED_VALUE, actual_value);
}

#[test]
fn should_call_session_code_and_compare_my_stored_value() {
    let mut builder = InMemoryWasmTestBuilder::default();
    builder
        .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
        .commit();

    let session_code = PathBuf::from(CONTRACT_WASM);
    let session_args = RuntimeArgs::new();

    let deploy_item = DeployItemBuilder::new()
        .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
        .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
        .with_address(*DEFAULT_ACCOUNT_ADDR)
        .with_session_code(session_code, session_args)
        .build();

    let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
    builder.exec(execute_request).commit().expect_success();

    let session_call = ExecuteRequestBuilder::standard(
        *DEFAULT_ACCOUNT_ADDR,
        NAMED_KEY_SESSION_WASM,
        runtime_args! {
            ARG_MY_STORED_VALUE => MY_STORED_VALUE,
        },
    )
    .build();

    builder.exec(session_call).expect_success().commit();
}
