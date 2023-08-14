## ComposableCoW + CompoundGovernor / GovernorBravo

This repository contains test suites for building proposals for CompoundGovernor / OpenZeppelin GovernorBravo. The repository is designed with [foundry](https://book.getfoundry.sh).

## Usage

The test suite is designed to run in a **forked** environment. Running in a self-contained environment is out of scope due to the large number of dependencies that are required. To run the test suite:

```bash
forge test -vvv --optimize --optimizer-runs 200 --rpc-url http://erigon.dappnode:8545 --fork-block-number 17885110
```

**NOTE**: Substitute the `RPC_URL` and the `fork-block-number` as required. Using a consistent `fork-block-number` will cache state that is pulled from the `RPC_URL`, resulting in substantially faster runtime on subsequent runs.

**NOTE**: There is a test item that is designed to **always revert** and alert any repository fork to ensure that *todo* items are completed.

### Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.
