// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

// General libraries
import {IERC20Metadata} from "openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {Create2} from "openzeppelin/contracts/utils/Create2.sol";
import {BytesLib} from "byteslib/BytesLib.sol";
import {IERC20} from "composable/lib/@openzeppelin/contracts/interfaces/IERC20.sol";

// Safe
import {Enum} from "safe/common/Enum.sol";
import {SafeProxyFactory} from "safe/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "safe/proxies/SafeProxy.sol";
import {Safe} from "safe/Safe.sol";
import {MultiSend} from "safe/libraries/MultiSend.sol";
import {ExtensibleFallbackHandler} from "safe/handler/ExtensibleFallbackHandler.sol";

// CoW Protocol + ComposableCoW
import {IConditionalOrder} from "composable/src/interfaces/IConditionalOrder.sol";
import {IValueFactory} from "composable/src/interfaces/IValueFactory.sol";
import {ComposableCoW} from "composable/src/ComposableCoW.sol";
import {TWAP, TWAPOrder} from "composable/src/types/twap/TWAP.sol";
import {CurrentBlockTimestampFactory} from "composable/src/value_factories/CurrentBlockTimestampFactory.sol";
import {GPv2Settlement} from "composable/lib/cowprotocol/src/contracts/GPv2Settlement.sol";

// DAO contracts
import {NounsDAOLogicV2} from "nounsdao/governance/NounsDAOLogicV2.sol";
import {NounsDAOExecutor} from "nounsdao/governance/NounsDAOExecutor.sol";
import {NounsToken} from "nounsdao/NounsToken.sol";

// Misc Tokens
import {IWstETH} from "../src/interfaces/IWstETH.sol";

// --- constants

// Safe
SafeProxyFactory constant safeFactory = SafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);
Safe constant safeSingleton = Safe(payable(0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552));
MultiSend constant multisend = MultiSend(0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761);
ExtensibleFallbackHandler constant efh = ExtensibleFallbackHandler(0x2f55e8b20D0B9FEFA187AA7d00B6Cbe563605bF5);

// CoW Protocol + ComposableCoW
GPv2Settlement constant settlement = GPv2Settlement(payable(0x9008D19f58AAbD9eD0D60971565AA8510560ab41));
address constant relayer = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;
ComposableCoW constant ccow = ComposableCoW(0xfdaFc9d1902f4e0b84f65F49f244b32b31013b74);
TWAP constant twap = TWAP(0x6cF1e9cA41f7611dEf408122793c358a3d11E5a5);
CurrentBlockTimestampFactory constant contextFactory = CurrentBlockTimestampFactory(0x52eD56Da04309Aca4c3FECC595298d80C2f16BAc);

// DAO + DAO Token
NounsDAOLogicV2 constant dao = NounsDAOLogicV2(payable(0x6f3E6272A167e8AcCb32072d08E0957F9c79223d));
NounsDAOExecutor constant timelock = NounsDAOExecutor(payable(0x0BC3807Ec262cB779b38D65b38158acC3bfedE10));
NounsToken constant nouns = NounsToken(0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03);
address constant auctionHouse = 0x830BD73E4184ceF73443C15111a1DF14e495C706;

// Tokens
address constant wstETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
IERC20Metadata constant stETH = IERC20Metadata(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
IERC20Metadata constant rETH = IERC20Metadata(0xae78736Cd615f374D3085123A210448E74Fc6393);

contract ProposalTest is Test {

    // Want to demonstrate setting up a vote and executing a swap of 500 wstETH to rETH
    // 1. Approve the required amount of stETH required to wrap into wstETH
    // 2. Wrap stETH into wstETH
    // 3. Create the `ComposableCoW` compatible `Safe` contract with:
    //   - `threshold` of 1
    //   - `owner` set to the `NounsDAOExecutor` address (ie. all executions on the `Safe` are bound by timelock)
    // 4. Send the wstETH from (2) to the `Safe` contract from (3).
    // 5. Approve the `GPv2VaultRelayer` to use `wstETH` from (4) to trade.
    // 6. Call `createWithContext` on `ComposableCoW` via the `Safe` contract from (3) with:
    //   - `sellToken` set to the wstETH address
    //   - `buyToken` set to the rETH address
    //   - `sellAmount` set to 500
    //   - `buyAmount` TBD
    //   - `receiver` set to the `NounsDAOExecutor` address (all funds on swap move to the timelock)
    // 
    // Risks: If a discrete order fails, that part of the swap will be left in the `Safe` contract.
    //        Funds are still retrievable, however as the `Safe` contract is owned by the `NounsDAOExecutor`
    //        the funds will be locked for the duration of the timelock.
    //
    // Process: 
    // 1. Prove that the process can be undertaken from the context of the `NounsDAOExecutor` (ie. the timelock).
    //    This means we use `vm.prank` to impersonate the `NounsDAOExecutor` and execute the swap.
    // 2. Create the proposal calldata.

    uint256 constant TOTAL_SELL = 500;
    uint256 constant TOTAL_BUY_FACTOR = 10380; // in BPS, 1wstETH = 1.038 rETH
    uint256 constant NUM_PARTS = 5;
    uint256 constant PART_DURATION = 2 hours;
    bytes32 constant SALT_NONCE = keccak256("moo");
    uint256 constant MAX_BPS = 10000;

    function testSwap_FromProposal() public {
        address[] memory targets = new address[](6);
        uint256[] memory values = new uint256[](6);
        string[] memory signatures = new string[](6);
        bytes[] memory calldatas = new bytes[](6);
        string memory description = "Swap 500 wstETH for rETH";

        bytes memory tempData;

        // all values are zero, set them to zero explicitly
        for (uint256 i = 0; i < values.length; i++) {
            values[i] = 0;
        }

        (bytes memory initializer, address pendingSafe) = getSafe(address(timelock), SALT_NONCE);
        uint256 stETHAmount = IWstETH(wstETH).getStETHByWstETH(tradeSize());

        // 1. Approve the required amount of stETH required to wrap into wstETH
        targets[0] = address(stETH);
        signatures[0] = "approve(address,uint256)";
        tempData = abi.encodeWithSelector(
            IERC20.approve.selector,
            wstETH,
            stETHAmount
        );
        calldatas[0] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // 2. Wrap stETH into wstETH
        targets[1] = address(wstETH);
        signatures[1] = "wrap(uint256)";
        tempData = abi.encodeWithSelector(
            IWstETH.wrap.selector,
            stETHAmount
        );
        calldatas[1] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // 3. Approve the to-be-created `Safe` contract to use the wstETH
        targets[2] = address(wstETH);
        signatures[2] = "approve(address,uint256)";
        tempData = abi.encodeWithSelector(
            IERC20.approve.selector,
            pendingSafe,
            tradeSize()
        );
        calldatas[2] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // 4. Create the safe
        targets[3] = address(safeFactory);
        signatures[3] = "createProxyWithNonce(address,bytes,uint256)";
        tempData = abi.encodeWithSelector(
            SafeProxyFactory.createProxyWithNonce.selector,
            address(safeSingleton),
            initializer,
            uint256(SALT_NONCE)
        );
        calldatas[3] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // 5. Configure the safe and create the TWAP
        bytes[] memory safeConfig = configureSafe(address(pendingSafe));
        targets[4] = address(pendingSafe);
        signatures[4] = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
        tempData = abi.encodeWithSelector(
            Safe.execTransaction.selector,
            address(multisend),
            0,
            abi.encodeWithSelector(
                MultiSend.multiSend.selector,
                abi.encodePacked(
                    // 1. Set the domainVerifier
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(pendingSafe),
                        uint256(0),
                        safeConfig[0].length,
                        safeConfig[0]
                    ),
                    // 2. Set the allowance on wstETH for `GPv2VaultRelayer`
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(wstETH),
                        uint256(0),
                        safeConfig[1].length,
                        safeConfig[1]
                    ),
                    // 3. Use `transferFrom` to pull funds from the timelock which has already approved the safe
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(wstETH),
                        uint256(0),
                        safeConfig[2].length,
                        safeConfig[2]
                    ),
                    // 4. Create the order
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(ccow),
                        uint256(0),
                        safeConfig[3].length,
                        safeConfig[3]
                    )
                )
            ),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(bytes32(uint256(uint160(address(timelock)))), bytes32(0), bytes1(uint8(1)))
        );
        calldatas[4] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // 6. Enforce that the allowance for `wstETH` to be spent from the timelock controller is set back to zero
        targets[5] = address(wstETH);
        signatures[5] = "approve(address,uint256)";
        tempData = abi.encodeWithSelector(
            IERC20.approve.selector,
            pendingSafe,
            0
        );
        calldatas[5] = BytesLib.slice(tempData, 4, tempData.length - 4);

        // Before we propose, set a fake low proposal threshold
        vm.startPrank(address(timelock));
        dao._setProposalThresholdBPS(1);
        dao._setMinQuorumVotesBPS(200);
        vm.stopPrank();

        address voter = address(this);

        // Let's fake being the NounsAuctionHoues and mint ourselves 60% of the nouns
        vm.startPrank(auctionHouse);
        for (uint256 i = 0; i < 400; i++) {
            uint256 id = nouns.mint();
            nouns.transferFrom(auctionHouse, voter, id);
        }
        vm.stopPrank();

        vm.roll(block.number + 1);

        // Can use our own account and ram it through now!
        uint256 proposalId = dao.propose(
            targets,
            values,
            signatures,
            calldatas,
            description
        );

        // Let's accelerate things for testing...
        // Roll forward by the voting delay
        vm.roll(block.number + dao.votingDelay() + 1);

        // Vote for the proposal
        dao.castVote(proposalId, 1);

        // Roll forward by the voting period
        vm.roll(block.number + dao.votingPeriod());

        // Attempt to queue the proposal
        dao.queue(proposalId);

        // There's a timelock period to wait for as well, let's warp!
        vm.warp(block.timestamp + timelock.delay() + 1);

        // Attempt to execute the proposal
        dao.execute(proposalId);
    }

    function testSwap_FromTimelockPerspective() public {
        require(NUM_PARTS < tradeSize());

        (bytes memory initializer, address pendingSafe) = getSafe(address(timelock), SALT_NONCE);

        // Do everything from the timelock
        vm.startPrank(address(timelock));

        // Calculate how much stETH we need to wrap to get 500 wstETH
        uint256 stETHAmount = IWstETH(wstETH).getStETHByWstETH(tradeSize());

        // 1. Approve the required amount of stETH required to wrap into wstETH
        stETH.approve(wstETH, stETHAmount);

        // 2. Wrap stETH into wstETH
        IWstETH(wstETH).wrap(stETHAmount);

        // 3. Approve the to-be-created `Safe` contract to use the wstETH
        IERC20(wstETH).approve(pendingSafe, tradeSize());

        // 4. Create the Safe.
        SafeProxy safe = safeFactory.createProxyWithNonce(
            address(safeSingleton),
            initializer,
            uint256(SALT_NONCE)
        );

        assertEq(address(safe), pendingSafe);

        // 5. On the safe, we need to do some configuration:
        //   a. Set `ComposableCoW` as the domain verifier for `GPv2Settlement`
        //   b. Set an allowance for `GPv2VaultRelayer` to use the wstETH
        //   c. Do `transferFrom` of the wstETH to the `Safe` contract
        //   d. Create the TWAP order on `ComposableCoW` via the `Safe` contract

        bytes[] memory safeConfig = configureSafe(address(safe));

        Safe(payable(address(safe))).execTransaction(
            address(multisend),
            0,
            abi.encodeWithSelector(
                MultiSend.multiSend.selector,
                abi.encodePacked(
                    // 1. Set the domainVerifier
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(safe),
                        uint256(0),
                        safeConfig[0].length,
                        safeConfig[0]
                    ),
                    // 2. Set the allowance on wstETH for `GPv2VaultRelayer`
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(wstETH),
                        uint256(0),
                        safeConfig[1].length,
                        safeConfig[1]
                    ),
                    // 3. Use `transferFrom` to pull funds from the timelock which has already approved the safe
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(wstETH),
                        uint256(0),
                        safeConfig[2].length,
                        safeConfig[2]
                    ),
                    // 4. Create the order
                    abi.encodePacked(
                        uint8(Enum.Operation.Call),
                        address(ccow),
                        uint256(0),
                        safeConfig[3].length,
                        safeConfig[3]
                    )
                )
            ),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(bytes32(uint256(uint160(address(timelock)))), bytes32(0), bytes1(uint8(1))) // special signature here as called directly from owner with threshold 1
        );

        // 6. Enforce that the allowance for `wstETH` to be spent from the timelock controller is set back to zero
        IERC20(wstETH).approve(pendingSafe, 0);

        assertEq(IERC20(wstETH).allowance(address(timelock), address(safe)), 0);
    }

    function testReadyForProd() public {
        // 1. Check all TODO comments in the codebase
        // 2. Verify swap rates.
        assertEq(uint256(1), uint256(0));
    }

    /**
     * Get the parameters required to build a single-owner safe, and the address it will be at.
     * @param owner of the new safe to be created
     * @param nonce for creating a deterministic safe address
     * @return initializer to be passed to the safe proxy factory
     * @return address that the new safe will be at when created
     */
    function getSafe(address owner, bytes32 nonce) internal pure returns (bytes memory, address) {
        address[] memory owners = new address[](1);
        owners[0] = owner;

        bytes memory initializer = abi.encodeWithSelector(
            safeSingleton.setup.selector,
            owners,
            owners.length,
            address(0),
            bytes(""),
            address(efh), // fallbackHandler
            address(0),
            uint256(0),
            address(0)
        );

        address pendingSafe = computeSafeAddress(initializer, nonce);

        return (initializer, pendingSafe);
    }

    function configureSafe(address safe) internal view returns (bytes[] memory config) {
        config = new bytes[](4);

        // 1. Set the domain verifier
        config[0] = abi.encodeWithSelector(
            efh.setDomainVerifier.selector,
            settlement.domainSeparator(),
            address(ccow)
        );

        // 2. Set the allowance on the pending safe for `GPv2VaultRelayer` to spend `wstETH`
        config[1] = abi.encodeWithSelector(
            IERC20.approve.selector,
            relayer,
            tradeSize()
        );

        // 3. Use `transferFrom` to pull funds from the timelock which has already approved the safe
        config[2] = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            address(timelock),
            address(safe),
            tradeSize()
        );

        // 4. Create the TWAP order on `ComposableCoW` via the `Safe` contract
        config[3] = abi.encodeWithSelector(
            ComposableCoW.createWithContext.selector,
            IConditionalOrder.ConditionalOrderParams({
                handler: IConditionalOrder(address(twap)),
                salt: keccak256("cows love nouns"),
                staticInput: abi.encode(TWAPOrder.Data({
                    sellToken: IERC20(address(wstETH)),
                    buyToken: IERC20(address(rETH)),
                    receiver: address(timelock), // all funds go back to the timelock
                    partSellAmount: tradeSize() / NUM_PARTS,
                    minPartLimit: minBuyPartLimit(), // max price to pay for a unit of buyToken denominated in sellToken
                    t0: uint256(0), // setting this to zero commands block time at mining of proposal execution
                    n: NUM_PARTS,
                    t: PART_DURATION,
                    span: 0,
                    appData: keccak256("need some cool appdata") // TODO: verify the appdata that we need here
                }))
            }),
            IValueFactory(address(contextFactory)),
            bytes(""),
            true
        );
    }

    function tradeSize() internal view returns (uint256) {
        return TOTAL_SELL * (10 ** (IERC20Metadata(wstETH).decimals()));
    }

    function minBuyPartLimit() internal view returns (uint256) {
        return tradeSize() * TOTAL_BUY_FACTOR / MAX_BPS;
    }

    function computeSafeAddress(bytes memory initializer, bytes32 saltNonce) internal pure returns (address) {
        address from = address(safeFactory);
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), uint256(saltNonce)));
        bytes32 initCodeHash = keccak256(abi.encodePacked(safeFactory.proxyCreationCode(), uint256(uint160(address(safeSingleton)))));

        return Create2.computeAddress(salt, initCodeHash, from);
    }

}
