# How to Read and Write to Global State

This folder contains session code and unit tests demonstrating how to read and write data to global state using Rust.

The [installer session code](./contract/src/main.rs) starts by installing a contract on the blockchain and saving the contract hash under a named key. Then, it creates a URef, stores the value `true` under that URef, and then stores the URef under a named key. This session code uses `runtime::put_key` and `storage::write`.

The [named key session code](./client/named_key_session/src/main.rs) reads the contract hash and stored value using `runtime::get_key`. It verifies that the stored value matches the runtime argument provided using `storage::read`. 

The [unit tests](./tests/src/integration_tests.rs) in this repository verify that the session code above works correctly. The tests are divided in two parts:

- Testing the installation and named keys in an account's context
- Getting the named keys and testing storage read with a session call

## Running the Example Code

Prepare your environment with the following:

`make prepare`

Build the code and run the tests:

`make test`

Build the code without running tests:

`make build-contract`

## Further Reading

Visit the official Casper Network documentation for more information on:

- Concepts regarding [reading and writing to the blockchain](https://docs.casper.network/concepts/design/reading-and-writing-to-the-blockchain/)
- A tutorial on [reading and writing data to global state using Rust](https://docs.casper.network/resources/tutorials/advanced/storage-workflow/)
