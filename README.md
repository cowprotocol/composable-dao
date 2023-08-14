## ComposableCoW + CompoundGovernor / GovernorBravo

This repository contains test suites for building proposals for CompoundGovernor / OpenZeppelin GovernorBravo. The repository is designed with [foundry](https://book.getfoundry.sh).

### Example NounsDAO 500 `wstETH` -> `rETH`

Want to demonstrate setting up a vote and executing a swap of 500 `wstETH` to `rETH`

1. Approve the required amount of `stETH` to wrap into `wstETH`.
2. Wrap `stETH` into `wstETH`
3. Approve the to-be-created `Safe` (in pt. 4) to use the DAO's `wstETH`
4. Create the `ComposableCoW` compatible `Safe` contract with:
    - `threshold` of 1
    - `owner` set to the `NounsDAOExecutor` address (ie. all executions on the `Safe` are bound by timelock)
5. Execute post-Safe creation configuration and create conditional order:
a. Set `ComposableCoW` as the domain verifier for `GPv2Settlement`
b. Set an allowance for `GPv2VaultRelayer` to use the `wstETH` from the `Safe` contract
c. Do `transferFrom` of the wstETH to the `Safe` contract
d. Create the TWAP order on `ComposableCoW` via the `Safe` contract
    - `sellToken` set to the wstETH address
    - `buyToken` set to the rETH address
    - `sellAmount` set to 500 wstETH
    - `buyAmount` TBD
    - `receiver` set to the `NounsDAOExecutor` address (all funds on swap move to the timelock)
6. Enforce that the allowance for `wstETH` to be spent from the timelock controller is set back to zero

#### Risk Mitigation

1. Any `Safe` that is created that holds `NounsDAO` funds, must be subject to the timelock controller nature of `NounsDAOExecutor`.
2. The sole owner of the `Safe` shall be the `NounsDAOExecutor`.
3. **NO** funds are sent to the to-be-created `Safe` in the atomic transaction bundle, and are instead *pulled* from the `NounsDAOExecutor`. This avoids the unlikely situation where a pre-calculated `Safe` address (prior to `SafeProxyFactory.createProxyWithNonce`) has been determined incorrectly and funds are sent to an unrecoverable address.
4. Approvals for spending on `NounsDAOExecutor` from the to-be-created `Safe` are zeroed at the end of the transaction bundle (though, should already be zero). 

#### Verification Process

1. Prove that the process can be undertaken from the context of the `NounsDAOExecutor` (ie. the timelock).
   This means we use `vm.prank` to impersonate the `NounsDAOExecutor` and execute the swap.
2. Do a full-stack test that:
   - Proposes the transaction bundle
   - Vote on the proposal (to affirm).
   - Queue the proposal (on successful vote).
   - Execute the proposal (verify transaction bundle executes correctly).
   - **To be completed:** Verify via settlement that the discrete orders settle correctly.

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
