#[cfg(test)]
mod tests {
    use crate::utility::{
        constants::{
            ACCOUNT_USER_1, ACCOUNT_USER_2, ADD_KEYS_WASM, ARG_CONTRACT_HASH, ARG_KEY_NAME,
            ASSOCIATED_ACCOUNT, CONTRACT_CALL_WASM, CONTRACT_HASH, CONTRACT_WASM, ENTRYPOINT,
            INTERSECTION_RECEIPT,
        },
        support::assert_expected_error,
    };
    use casper_engine_test_support::{
        DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, ARG_AMOUNT,
        DEFAULT_ACCOUNT_ADDR, DEFAULT_ACCOUNT_INITIAL_BALANCE, DEFAULT_CHAINSPEC_REGISTRY,
        DEFAULT_GENESIS_CONFIG, DEFAULT_GENESIS_CONFIG_HASH, DEFAULT_PAYMENT,
        PRODUCTION_RUN_GENESIS_REQUEST,
    };
    use casper_execution_engine::core::{
        engine_state::GenesisAccount, engine_state::RunGenesisRequest,
    };
    use casper_types::{
        account::AccountHash, runtime_args, CLValue, ContractHash, Key, Motes, PublicKey,
        RuntimeArgs, SecretKey, U512,
    };
    use std::path::PathBuf;

    // Test Installation
    #[test]
    fn should_allow_install_contract_with_default_account() {
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
    }

    #[test]
    fn should_disallow_install_with_non_added_authorization_key() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = RuntimeArgs::new();

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR, account_addr_1])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, session_args)
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_failure();
        let error = builder.get_error().expect("must have error");
        assert_eq!(error.to_string(), "Authorization failure: not authorized.");
    }

    #[test]
    fn should_allow_install_with_added_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        // Add ACCOUNT_USER_1 to DEFAULT_ACCOUNT_ADDR associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => account_addr_1
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = RuntimeArgs::new();

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR, account_addr_1])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, session_args)
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();
    }

    // Test Entry point
    #[test]
    fn should_allow_entry_point_with_installer_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        // Add ACCOUNT_USER_1 to DEFAULT_ACCOUNT_ADDR associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => account_addr_1
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        let session_code = PathBuf::from(CONTRACT_WASM);

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR, account_addr_1])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, runtime_args! {})
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_HASH)
            .expect("must have this entry in named keys")
            .into_hash()
            .map(ContractHash::new)
            .unwrap();

        let entry_point_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1])
            .with_address(account_addr_1)
            .with_stored_session_hash(contract_hash, ENTRYPOINT, runtime_args! {})
            .build();

        let entry_point_request =
            ExecuteRequestBuilder::from_deploy_item(entry_point_deploy_item).build();

        builder.exec(entry_point_request).expect_success().commit();
    }

    #[test]
    fn should_allow_entry_point_with_account_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        let session_code = PathBuf::from(CONTRACT_WASM);

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, runtime_args! {})
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_HASH)
            .expect("must have this entry in named keys")
            .into_hash()
            .map(ContractHash::new)
            .unwrap();

        // Add DEFAULT_ACCOUNT_ADDR to ACCOUNT_USER_1 associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => *DEFAULT_ACCOUNT_ADDR
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        let entry_point_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1, *DEFAULT_ACCOUNT_ADDR])
            .with_address(account_addr_1)
            .with_stored_session_hash(contract_hash, ENTRYPOINT, runtime_args! {})
            .build();

        let entry_point_request =
            ExecuteRequestBuilder::from_deploy_item(entry_point_deploy_item).build();

        builder.exec(entry_point_request).expect_success().commit();
    }

    #[test]
    fn should_disallow_entry_point_without_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_2).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_2 = AccountHash::from(&public_key);
        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        let session_code = PathBuf::from(CONTRACT_WASM);

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, runtime_args! {})
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_HASH)
            .expect("must have this entry in named keys")
            .into_hash()
            .map(ContractHash::new)
            .unwrap();

        // Add DEFAULT_ACCOUNT_ADDR to ACCOUNT_USER_1 associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => *DEFAULT_ACCOUNT_ADDR
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        // We reach the same state as previous test but here ACCOUNT_USER_2 does not have contract installer (DEFAULT_ACCOUNT_ADDR) in associated keys.
        // Deploy will therefore revert with PermissionDenied
        let entry_point_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_2])
            .with_address(account_addr_2)
            .with_stored_session_hash(contract_hash, ENTRYPOINT, runtime_args! {})
            .build();

        let entry_point_request =
            ExecuteRequestBuilder::from_deploy_item(entry_point_deploy_item).build();

        builder.exec(entry_point_request).commit().expect_failure();
        let error = builder.get_error().expect("must have User error: 0");
        assert_expected_error(
            error,
            0,
            "should fail execution since DEFAULT_ACCOUNT_ADDR is not in ACCOUNT_USER_2 associated keys",
        );
    }

    // Test Contract call to Entry point
    #[test]
    fn should_allow_entry_point_through_contract_call_with_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        let session_code = PathBuf::from(CONTRACT_WASM);

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, runtime_args! {})
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_HASH)
            .expect("must have this entry in named keys")
            .into_hash()
            .map(ContractHash::new)
            .unwrap();

        // Add DEFAULT_ACCOUNT_ADDR to ACCOUNT_USER_1 associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => *DEFAULT_ACCOUNT_ADDR
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        let session_code = PathBuf::from(CONTRACT_CALL_WASM);

        let session_args = runtime_args! {
            ARG_CONTRACT_HASH => Key::from(contract_hash),
            ARG_KEY_NAME => INTERSECTION_RECEIPT
        };

        let entry_point_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1, *DEFAULT_ACCOUNT_ADDR])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let entry_point_request =
            ExecuteRequestBuilder::from_deploy_item(entry_point_deploy_item).build();
        builder.exec(entry_point_request).expect_success().commit();

        let intersection_receipt: Key = *builder
            .get_expected_account(account_addr_1)
            .named_keys()
            .get(INTERSECTION_RECEIPT)
            .expect("must have this entry in named keys");

        let actual_intersection = builder
            .query(None, intersection_receipt, &[])
            .expect("must have stored_value")
            .as_cl_value()
            .map(|intersection_cl_value| {
                CLValue::into_t::<Vec<AccountHash>>(intersection_cl_value.clone())
            })
            .unwrap()
            .unwrap();

        let expected_intersection = vec![*DEFAULT_ACCOUNT_ADDR];

        assert_eq!(actual_intersection, expected_intersection);
    }

    #[test]
    fn should_disallow_entry_point_through_contract_call_without_authorization_key() {
        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_1).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_1 = AccountHash::from(&public_key);

        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );

        let mut genesis_config = DEFAULT_GENESIS_CONFIG.clone();
        genesis_config.ee_config_mut().push_account(account);

        let secret_key = SecretKey::ed25519_from_bytes(ACCOUNT_USER_2).unwrap();
        let public_key = PublicKey::from(&secret_key);
        let account_addr_2 = AccountHash::from(&public_key);
        let account = GenesisAccount::account(
            public_key,
            Motes::new(U512::from(DEFAULT_ACCOUNT_INITIAL_BALANCE)),
            None,
        );
        genesis_config.ee_config_mut().push_account(account);

        let run_genesis_request = RunGenesisRequest::new(
            *DEFAULT_GENESIS_CONFIG_HASH,
            genesis_config.protocol_version(),
            genesis_config.take_ee_config(),
            DEFAULT_CHAINSPEC_REGISTRY.clone(),
        );

        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&run_genesis_request).commit();

        let session_code = PathBuf::from(CONTRACT_WASM);

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, runtime_args! {})
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_HASH)
            .expect("must have this entry in named keys")
            .into_hash()
            .map(ContractHash::new)
            .unwrap();

        // Add DEFAULT_ACCOUNT_ADDR to ACCOUNT_USER_1 associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => *DEFAULT_ACCOUNT_ADDR
        };

        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        // Add ACCOUNT_USER_2 to ACCOUNT_USER_1 associated keys
        let session_code = PathBuf::from(ADD_KEYS_WASM);
        let session_args = runtime_args! {
            ASSOCIATED_ACCOUNT => account_addr_2
        };

        // Threshold is now 2 for ACCOUNT_USER_1 deploys
        let add_keys_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1, *DEFAULT_ACCOUNT_ADDR])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let add_keys_execute_request =
            ExecuteRequestBuilder::from_deploy_item(add_keys_deploy_item).build();

        builder
            .exec(add_keys_execute_request)
            .commit()
            .expect_success();

        let session_code = PathBuf::from(CONTRACT_CALL_WASM);

        let session_args = runtime_args! {
            ARG_CONTRACT_HASH => Key::from(contract_hash),
            ARG_KEY_NAME => INTERSECTION_RECEIPT
        };

        // ACCOUNT_USER_2 as associated key is not among contract installer (DEFAULT_ACCOUNT_ADDR) associated keys
        // Deploy will therefore revert with PermissionDenied
        let entry_point_deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[account_addr_1, account_addr_2])
            .with_address(account_addr_1)
            .with_session_code(session_code, session_args)
            .build();

        let entry_point_request =
            ExecuteRequestBuilder::from_deploy_item(entry_point_deploy_item).build();

        builder.exec(entry_point_request).commit().expect_failure();

        let error = builder.get_error().expect("must have User error: 0");
        assert_expected_error(
            error,
            0,
            "should fail execution since ACCOUNT_USER_2 as associated key is not in installer (DEFAULT_ACCOUNT_ADDR) associated keys",
        );
    }
}
