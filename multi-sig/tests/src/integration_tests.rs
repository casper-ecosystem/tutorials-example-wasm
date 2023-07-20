#[cfg(test)]
mod tests {
    use casper_execution_engine::core::{engine_state::Error as EngineStateError, execution};
    use std::path::PathBuf;

    use add_account::constants::{
        RUNTIME_ARG_NEW_ASSOCIATED_KEY, RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT,
    };
    use casper_engine_test_support::{
        DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, ARG_AMOUNT,
        DEFAULT_ACCOUNT_ADDR, DEFAULT_PAYMENT, PRODUCTION_RUN_GENESIS_REQUEST,
    };
    use casper_types::{account::Weight, runtime_args, ApiError, Key, RuntimeArgs};
    use remove_account::constants::RUNTIME_ARG_REMOVE_ASSOCIATED_KEY;
    use tests::constants::{
        ADD_ACCOUNT_WASM, CONTRACT_WASM, KEY_NAME, REMOVE_ACCOUNT_WASM, RUNTIME_ARG_NAME,
        TEST_VALUE, UPDATE_KEYS_WASM, UPDATE_THRESHOLDS_WASM, USER_1_ACCOUNT, USER_2_ACCOUNT,
    };
    use update_associated_keys::constants::{
        RUNTIME_ARG_ASSOCIATED_KEY, RUNTIME_ARG_NEW_KEY_WEIGHT,
    };
    use update_thresholds::constants::{
        RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD, RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD,
    };

    #[test]
    fn should_update_primary_key_weight() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        let expected_key_weight = Weight::new(3);

        let update_weight_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_KEYS_WASM,
            runtime_args! {
                RUNTIME_ARG_ASSOCIATED_KEY => Key::from(*DEFAULT_ACCOUNT_ADDR),
                RUNTIME_ARG_NEW_KEY_WEIGHT => expected_key_weight,
            },
        )
        .build();

        builder
            .exec(update_weight_request)
            .expect_success()
            .commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");
        let actual_weight = account
            .associated_keys()
            .get(&DEFAULT_ACCOUNT_ADDR)
            .unwrap();

        assert_eq!(actual_weight, &expected_key_weight);
    }

    #[test]
    fn should_add_new_accounts_to_primary_associated_keys() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // Add User Account 1 to the Default Account Associated Keys
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_1_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_success().commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");
        let actual_weight = account.associated_keys().get(&USER_1_ACCOUNT).unwrap();

        assert_eq!(actual_weight, &Weight::new(1));

        // Add User Account 2 to the Default Account Associated Keys
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_2_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_success().commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");
        let actual_weight = account.associated_keys().get(&USER_2_ACCOUNT).unwrap();

        assert_eq!(actual_weight, &Weight::new(1));
    }

    #[test]
    fn should_update_primary_key_weight_and_thresholds() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        let update_weight_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_KEYS_WASM,
            runtime_args! {
                RUNTIME_ARG_ASSOCIATED_KEY => Key::from(*DEFAULT_ACCOUNT_ADDR),
                RUNTIME_ARG_NEW_KEY_WEIGHT => Weight::new(3),
            },
        )
        .build();

        builder
            .exec(update_weight_request)
            .expect_success()
            .commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");
        let actual_weight = account
            .associated_keys()
            .get(&DEFAULT_ACCOUNT_ADDR)
            .unwrap();
        assert_eq!(actual_weight, &Weight::new(3));

        let update_threshold_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_THRESHOLDS_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD =>  Weight::new(2),
                RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD => Weight::new(3),
            },
        )
        .build();

        builder
            .exec(update_threshold_request)
            .expect_success()
            .commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");

        let key_mgmt_threshold = account.action_thresholds().key_management();
        let deployment_threshold = account.action_thresholds().deployment();

        assert_eq!(key_mgmt_threshold, &Weight::new(3));
        assert_eq!(deployment_threshold, &Weight::new(2));
    }

    #[test]
    fn should_add_two_keys_and_remove_one() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // Add User Account 1 to the Default Account Associated Keys
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_1_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_success().commit();

        // Add User Account 2 to the Default Account Associated Keys
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_2_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_success().commit();

        // Remove User Account 1 to the Default Account Associated Keys
        let contract_installation_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            REMOVE_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_REMOVE_ASSOCIATED_KEY => Key::from(USER_1_ACCOUNT)
                ,
            },
        )
        .build();

        builder
            .exec(contract_installation_request)
            .expect_success()
            .commit();

        // Prepare assertions.
        let account = builder
            .get_account(*DEFAULT_ACCOUNT_ADDR)
            .expect("Should be an account.");

        let missing_account_weight = account.associated_keys().get(&USER_1_ACCOUNT);

        assert_eq!(missing_account_weight, None);

        let existing_account_weight = account.associated_keys().get(&USER_2_ACCOUNT).unwrap();

        assert_eq!(existing_account_weight, &Weight::new(1));
    }

    #[test]
    fn should_store_hello_world() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // The test framework checks for compiled Wasm files in '<current working dir>/wasm'.  Paths
        // relative to the current working dir (e.g. 'wasm/contract.wasm') can also be used, as can
        // absolute paths.
        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = runtime_args! {
            RUNTIME_ARG_NAME => TEST_VALUE,
        };

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code, session_args)
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        // prepare assertions.
        let result_of_query = builder.query(
            None,
            Key::Account(*DEFAULT_ACCOUNT_ADDR),
            &[KEY_NAME.to_string()],
        );
        assert!(result_of_query.is_err());

        // deploy the contract.
        builder.exec(execute_request).commit().expect_success();

        // make assertions
        let result_of_query = builder
            .query(
                None,
                Key::Account(*DEFAULT_ACCOUNT_ADDR),
                &[KEY_NAME.to_string()],
            )
            .expect("should be stored value.")
            .as_cl_value()
            .expect("should be cl value.")
            .clone()
            .into_t::<String>()
            .expect("should be string.");

        assert_eq!(result_of_query, TEST_VALUE);
    }

    #[test]
    fn should_check_thresholds_errors() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // Step 3: Increase the primary key's weight to set thresholds
        let update_weight_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_KEYS_WASM,
            runtime_args! {
                RUNTIME_ARG_ASSOCIATED_KEY => Key::from(*DEFAULT_ACCOUNT_ADDR),
                RUNTIME_ARG_NEW_KEY_WEIGHT => Weight::new(2),
            },
        )
        .build();
        builder
            .exec(update_weight_request)
            .expect_success()
            .commit();

        // Step 4: Update the default account's action thresholds
        let update_threshold_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_THRESHOLDS_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD =>  Weight::new(2),
                RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD => Weight::new(2),
            },
        )
        .build();

        builder
            .exec(update_threshold_request)
            .expect_success()
            .commit();

        // Step 5: Add associated keys to the primary account
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_1_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        // This request should succeed as DEFAULT_ACCOUNT_ADDR has weight 2, equal key management threshold && deployment threshold
        builder.exec(add_key_request).expect_success().commit();

        // Step 6: Send a multi-signature deploy from the primary account
        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = runtime_args! {
            RUNTIME_ARG_NAME => TEST_VALUE,
        };

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code, session_args)
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item.clone()).build();

        // This request should succeed as DEFAULT_ACCOUNT_ADDR has weight 2, equal deployment threshold
        builder.exec(deploy_request).expect_success().commit();

        // Let's test if a decreased weight for DEFAULT_ACCOUNT_ADDR blocks deployement
        let update_weight_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_KEYS_WASM,
            runtime_args! {
                RUNTIME_ARG_ASSOCIATED_KEY => Key::from(*DEFAULT_ACCOUNT_ADDR),
                RUNTIME_ARG_NEW_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder
            .exec(update_weight_request)
            .commit()
            .expect_success();

        // This deploy request should fail as DEFAULT_ACCOUNT_ADDR has weight 1, below deployment threshold of 2
        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(deploy_request).expect_failure();

        let actual_error = builder.get_error().expect("must have error");
        assert!(
            matches!(
                actual_error,
                EngineStateError::Exec(execution::Error::DeploymentAuthorizationFailure)
            ),
            "Expected {:?}, received {:?}",
            EngineStateError::Exec(execution::Error::DeploymentAuthorizationFailure),
            actual_error
        );

        // Let's decrease deployement threshold to meet DEFAULT_ACCOUNT_ADDR weight
        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT,
            })
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR, USER_1_ACCOUNT])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(
                UPDATE_THRESHOLDS_WASM,
                runtime_args! {
                    RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD =>  Weight::new(1),
                    RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD => Weight::new(2),
                },
            )
            .build();

        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();
        builder.exec(deploy_request).expect_success().commit();

        // This request should fail as DEFAULT_ACCOUNT_ADDR has weight 1, still below key management threshold of 2
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_2_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_failure();

        let actual_error = builder.get_error().expect("must have error");
        assert!(
            matches!(
                actual_error,
                EngineStateError::Exec(execution::Error::Revert(ApiError::PermissionDenied))
            ),
            "Expected {:?}, received {:?}",
            EngineStateError::Exec(execution::Error::Revert(ApiError::PermissionDenied)),
            actual_error
        );
    }

    #[test]
    fn should_execute_tutorial_steps() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // Step 3: Increase the primary key's weight to set thresholds
        let update_weight_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_KEYS_WASM,
            runtime_args! {
                RUNTIME_ARG_ASSOCIATED_KEY => Key::from(*DEFAULT_ACCOUNT_ADDR),
                RUNTIME_ARG_NEW_KEY_WEIGHT => Weight::new(3),
            },
        )
        .build();
        builder
            .exec(update_weight_request)
            .expect_success()
            .commit();

        // Step 4: Update the default account's action thresholds
        let update_threshold_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            UPDATE_THRESHOLDS_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_DEPLOYMENT_THRESHOLD =>  Weight::new(2),
                RUNTIME_ARG_NEW_KEY_MANAGEMENT_THRESHOLD => Weight::new(3),
            },
        )
        .build();

        builder
            .exec(update_threshold_request)
            .expect_success()
            .commit();

        // Step 5: Add associated keys to the primary account
        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_1_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        builder.exec(add_key_request).expect_success().commit();

        let add_key_request = ExecuteRequestBuilder::standard(
            *DEFAULT_ACCOUNT_ADDR,
            ADD_ACCOUNT_WASM,
            runtime_args! {
                RUNTIME_ARG_NEW_ASSOCIATED_KEY => Key::from(USER_2_ACCOUNT),
                RUNTIME_ARG_NEW_ASSOCIATED_KEY_WEIGHT => Weight::new(1),
            },
        )
        .build();

        // This request should succeed as DEFAULT_ACCOUNT_ADDR has weight 3, above or equal key management threshold && deployment threshold
        builder.exec(add_key_request).expect_success().commit();

        // Step 6: Send a deploy from the primary account
        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = runtime_args! {
            RUNTIME_ARG_NAME => TEST_VALUE,
        };

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code.clone(), session_args.clone())
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        // This request should succeed as DEFAULT_ACCOUNT_ADDR has weight 3, greater than the deployment threshold
        builder.exec(deploy_request).expect_success().commit();

        // Step 7: Send a multi-signature deploy from an associated key

        // This deploy request should fail as USER_1_ACCOUNT has weight 1, below deployment threshold of 2
        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code.clone(), session_args.clone())
            .with_authorization_keys(&[USER_1_ACCOUNT])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        builder.exec(deploy_request).expect_failure();

        // This deploy request should succeed as USER_1_ACCOUNT + USER_2_ACCOUNT have weight 2, equal deployment threshold of 2

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code, session_args)
            .with_authorization_keys(&[USER_1_ACCOUNT, USER_2_ACCOUNT])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let deploy_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        builder.exec(deploy_request).expect_success().commit();
    }
}

fn main() {
    panic!("Execute \"cargo test\" to test the contract, not \"cargo run\".");
}
