# authorization-keys-example

This simple example demonstrates retrieving and using the authorization keys associated with a Deploy.

The contract code in this example retrieves the set of authorization keys for a given deploy by calling the `runtime::list_authorization_keys` function. In other words, `list_authorization_keys` returns the set of account hashes representing the keys used to sign a deploy. 

Upon installation, the contract code stores the authorization keys for the installer deploy into a NamedKey. The contract also contains an entry point that returns the intersection of the caller deploy's, and installer deploy's authorization keys. The tests in this repository verify different scenarios and check the resulting intersection.

Read the [Working with Authorization Keys](./tutorial/TUTORIAL.md) tutorial for additional information.

## Running the Example Code

Prepare your environment with the following:

`make prepare`

Build the code and run the tests:

`make test`

Build the code without running tests:

`make build-contract`
