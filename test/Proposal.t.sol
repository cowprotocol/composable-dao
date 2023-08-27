// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

// General libraries
import {IERC20Metadata} from "openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {Create2} from "openzeppelin/contracts/utils/Create2.sol";
import {BytesLib} from "byteslib/BytesLib.sol";
import {IERC20} from "composable/lib/@openzeppelin/contracts/interfaces/IERC20.sol";
import {TestAccount, TestAccountLib} from "composable/test/libraries/TestAccountLib.t.sol";

// Safe
import {Enum} from "safe/common/Enum.sol";
import {SafeProxyFactory} from "safe/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "safe/proxies/SafeProxy.sol";
import {Safe} from "safe/Safe.sol";
import {MultiSend} from "safe/libraries/MultiSend.sol";
import {ExtensibleFallbackHandler} from "safe/handler/ExtensibleFallbackHandler.sol";
import {ERC1271} from "safe/handler/extensible/SignatureVerifierMuxer.sol";

// CoW Protocol + ComposableCoW
import {IConditionalOrder} from "composable/src/interfaces/IConditionalOrder.sol";
import {IValueFactory} from "composable/src/interfaces/IValueFactory.sol";
import {ComposableCoW} from "composable/src/ComposableCoW.sol";
import {TWAP, TWAPOrder} from "composable/src/types/twap/TWAP.sol";
import {CurrentBlockTimestampFactory} from "composable/src/value_factories/CurrentBlockTimestampFactory.sol";
import {GPv2Settlement} from "composable/lib/cowprotocol/src/contracts/GPv2Settlement.sol";
import {GPv2TradeEncoder} from "composable/test/vendored/GPv2TradeEncoder.sol";
import {GPv2Order} from "composable/lib/cowprotocol/src/contracts/libraries/GPv2Order.sol";
import {GPv2Trade} from "composable/lib/cowprotocol/src/contracts/libraries/GPv2Trade.sol";
import {GPv2Interaction} from "composable/lib/cowprotocol/src/contracts/libraries/GPv2Interaction.sol";
import {GPv2Signing} from "composable/lib/cowprotocol/src/contracts/mixins/GPv2Signing.sol";
import {GPv2AllowListAuthentication} from "composable/lib/cowprotocol/src/contracts/GPv2AllowListAuthentication.sol";

// Misc Tokens
import {IWstETH} from "../src/interfaces/IWstETH.sol";

// NounsDAO Specifics
import "../src/interfaces/NounsDAOContracts.sol";

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
CurrentBlockTimestampFactory constant contextFactory =
    CurrentBlockTimestampFactory(0x52eD56Da04309Aca4c3FECC595298d80C2f16BAc);
GPv2AllowListAuthentication constant allowList = GPv2AllowListAuthentication(0x2c4c28DDBdAc9C5E7055b4C863b72eA0149D8aFE);

// DAO + DAO Token
INounsDAOLogic constant dao = INounsDAOLogic(payable(0x6f3E6272A167e8AcCb32072d08E0957F9c79223d));
// Post proposal 356, the timelock has moved to the new executor
INounsTimelock constant timelock = INounsTimelock(payable(0xb1a32FC9F9D8b2cf86C068Cae13108809547ef71));
INounsToken constant nouns = INounsToken(0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03);
address constant auctionHouse = 0x830BD73E4184ceF73443C15111a1DF14e495C706;

// Tokens
address constant wstETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
IERC20Metadata constant stETH = IERC20Metadata(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
IERC20Metadata constant rETH = IERC20Metadata(0xae78736Cd615f374D3085123A210448E74Fc6393);

contract ProposalTest is Test {
    using TestAccountLib for TestAccount[];
    using TestAccountLib for TestAccount;
    // --- types

    struct ConfigSafe {
        address safe;
        address sellToken;
        uint256 sellAmount;
        address source;
        IConditionalOrder.ConditionalOrderParams params;
        address contextFactory;
        bytes contextFactoryPayload;
        bool postInit;
    }

    // --- constants
    IERC20 constant SELL_TOKEN = IERC20(address(wstETH));
    IERC20 constant BUY_TOKEN = IERC20(address(rETH));
    address constant SOURCE = address(timelock);
    address constant RECEIVER = address(timelock);
    uint256 constant TOTAL_SELL = 500;
    uint256 constant TOTAL_BUY_FACTOR = 10380; // todo: in BPS, 1wstETH = 1.038 rETH
    uint256 constant NUM_PARTS = 5;
    uint256 constant PART_DURATION = 2 hours;
    bytes32 constant SALT_NONCE = keccak256("moo"); // todo
    uint256 constant MAX_BPS = 10000;

    bytes32 constant CONDITIONAL_ORDER_SALT = keccak256("cows love nouns"); // todo
    bytes32 constant TWAP_APPDATA = keccak256("need some cool appdata"); // todo

    TestAccount solver = TestAccountLib.createTestAccount("solver");
    TestAccount bob = TestAccountLib.createTestAccount("counterParty");

    mapping(bytes32 => uint256) public orderFills;
    address voter;

    function setUp() public {
        // Current state:
        // - Proposal 359 will move the last of the NounsDAO TreasuryV1 to the new treasury
        ProposalCondensed memory propDetails = dao.proposals(359);

        // For the tests, move to the block before we must have enough tokens for voting.
        vm.roll(propDetails.startBlock - 1);

        // Now we mint enough nouns to be able to create and ram proposals through.

        // Before we propose, set a fake low proposal threshold
        vm.startPrank(address(timelock));
        dao._setProposalThresholdBPS(1);
        dao._setMinQuorumVotesBPS(200);
        vm.stopPrank();

        voter = address(this);

        // Let's fake being the NounsAuctionHouse and mint ourselves 60% of the nouns
        vm.startPrank(auctionHouse);
        for (uint256 i = 0; i < 400; i++) {
            uint256 id = nouns.mint();
            nouns.transferFrom(auctionHouse, voter, id);
        }
        vm.stopPrank();

        vm.roll(block.number + 2);

        // Now let's vote for the proposal, queue it, and execute it
        dao.castVote(359, 1);

        // Roll forward by the voting period
        vm.roll(block.number + dao.votingPeriod());

        // Attempt to queue the proposal
        dao.queue(359);

        // There's a timelock period to wait for as well, let's warp!
        vm.warp(block.timestamp + timelock.delay() + 1);

        // Attempt to execute the proposal
        dao.execute(359);
    }

    /**
     * Customise this function for the order you want to create for the proposal.
     */
    function getOrder() internal view returns (IConditionalOrder.ConditionalOrderParams memory) {
        return IConditionalOrder.ConditionalOrderParams({
            handler: IConditionalOrder(address(twap)),
            salt: CONDITIONAL_ORDER_SALT,
            staticInput: abi.encode(
                TWAPOrder.Data({
                    sellToken: SELL_TOKEN,
                    buyToken: BUY_TOKEN,
                    receiver: RECEIVER, // all funds go back to the timelock
                    partSellAmount: tradeSize() / NUM_PARTS,
                    minPartLimit: minBuyLimit() / NUM_PARTS, // minimum amount of rETH we want to get back per part
                    t0: uint256(0), // setting this to zero commands block time at mining of proposal execution
                    n: NUM_PARTS,
                    t: PART_DURATION,
                    span: 0,
                    appData: TWAP_APPDATA
                })
                )
        });
    }

    function testTWAP_SimulateFromProposal() public {
        address[] memory targets = new address[](6);
        uint256[] memory values = new uint256[](6);
        string[] memory signatures = new string[](6);
        bytes[] memory calldatas = new bytes[](6);
        string memory description = vm.readFile("proposal.txt");

        (bytes memory initializer, address STAGING_SAFE) = getSafe(RECEIVER, SALT_NONCE);
        uint256 stETHAmount = IWstETH(wstETH).getStETHByWstETH(tradeSize());

        // 1. Approve the required amount of stETH required to wrap into wstETH
        (targets[0], values[0], signatures[0], calldatas[0]) = interactionHelper(
            address(stETH),
            0,
            "approve(address,uint256)",
            abi.encodeWithSelector(IERC20.approve.selector, wstETH, stETHAmount)
        );

        // 2. Wrap stETH into wstETH
        (targets[1], values[1], signatures[1], calldatas[1]) = interactionHelper(
            address(wstETH), 0, "wrap(uint256)", abi.encodeWithSelector(IWstETH.wrap.selector, stETHAmount)
        );

        // 3. Approve the to-be-created `Safe` contract to use the wstETH
        (targets[2], values[2], signatures[2], calldatas[2]) = interactionHelper(
            address(SELL_TOKEN),
            0,
            "approve(address,uint256)",
            abi.encodeWithSelector(IERC20.approve.selector, STAGING_SAFE, tradeSize())
        );

        // 4. Create the safe (STAGING_SAFE)
        (targets[3], values[3], signatures[3], calldatas[3]) = interactionHelper(
            address(safeFactory),
            0,
            "createProxyWithNonce(address,bytes,uint256)",
            abi.encodeWithSelector(
                SafeProxyFactory.createProxyWithNonce.selector, address(safeSingleton), initializer, uint256(SALT_NONCE)
            )
        );

        // 5. Configure the safe and create the TWAP
        (targets[4], values[4], signatures[4], calldatas[4]) = configSafe(
            ConfigSafe({
                safe: STAGING_SAFE,
                sellToken: address(SELL_TOKEN),
                sellAmount: tradeSize(),
                source: SOURCE,
                params: getOrder(),
                contextFactory: address(contextFactory),
                contextFactoryPayload: bytes(""),
                postInit: true
            })
        );

        // 6. Enforce that the allowance for `wstETH` that can be spent from the timelock controller is set back to zero
        (targets[5], values[5], signatures[5], calldatas[5]) = interactionHelper(
            address(SELL_TOKEN),
            0,
            "approve(address,uint256)",
            abi.encodeWithSelector(IERC20.approve.selector, STAGING_SAFE, 0)
        );

        // Output the calldata as a string for easy copy-paste
        console2.logBytes(
            abi.encodeWithSelector(dao.propose.selector, targets, values, signatures, calldatas, description)
        );

        // Can use our own account and ram it through now!
        uint256 proposalId = dao.propose(targets, values, signatures, calldatas, description);

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
        uint256 t0 = block.timestamp;

        // --- simulation of the settlement
        vm.prank(allowList.manager());
        allowList.addSolver(solver.addr);

        // fund the counter-party with the rETH to swap for wstETH
        deal(address(BUY_TOKEN), bob.addr, tradeSize() * TOTAL_BUY_FACTOR / MAX_BPS);

        // Store balances before we simulate the settlements
        uint256 safeWstEthBalanceBefore = SELL_TOKEN.balanceOf(address(STAGING_SAFE));
        uint256 timelockRethBalanceBefore = BUY_TOKEN.balanceOf(RECEIVER);
        uint256 counterPartyWstEthBalanceBefore = SELL_TOKEN.balanceOf(bob.addr);
        uint256 counterPartyRethBalanceBefore = BUY_TOKEN.balanceOf(bob.addr);

        uint256 totalFills;
        uint256 numSecsProcessed;

        // calculate the ending time
        uint256 endTime = t0 + (NUM_PARTS * PART_DURATION);

        // the case for progressing beyond the end of the TWAP order (endTime) and checking for
        // reversion isn't handled here as it's handled within the `ComposableCoW` TWAP order
        // test suite.
        while (block.timestamp < endTime) {
            // Simulate being called by the watch tower
            (GPv2Order.Data memory order, bytes memory signature) =
                ccow.getTradeableOrderWithSignature(STAGING_SAFE, getOrder(), bytes(""), new bytes32[](0));
            bytes32 orderDigest = GPv2Order.hash(order, settlement.domainSeparator());
            if (
                orderFills[orderDigest] == 0
                    && ExtensibleFallbackHandler(STAGING_SAFE).isValidSignature(orderDigest, signature)
                        == ERC1271.isValidSignature.selector
            ) {
                // Have a new order, so let's settle it
                settle(STAGING_SAFE, bob, order, signature, bytes4(0));

                orderFills[orderDigest] = 1;
                totalFills++;
            }

            // only count this second if we didn't revert
            numSecsProcessed += 12 seconds;

            // warp in preparation for the next block
            vm.warp(block.timestamp + 12 seconds);
        }

        // the timestamp should be equal to the end time of the TWAP order
        assertTrue(block.timestamp == t0 + NUM_PARTS * PART_DURATION, "TWAP order should be expired");
        // the number of seconds processed should be equal to the number of
        // parts times span (if span is not 0)
        assertTrue(numSecsProcessed == NUM_PARTS * PART_DURATION, "Number of seconds processed is incorrect");
        // the number of fills should be equal to the number of parts
        assertTrue(totalFills == NUM_PARTS, "Number of fills is incorrect");

        // Verify that balances are as expected after the simulation
        assertTrue(
            SELL_TOKEN.balanceOf(address(STAGING_SAFE)) == safeWstEthBalanceBefore - tradeSize(),
            "TWAP safe sell token balance is incorrect"
        );
        assertTrue(
            BUY_TOKEN.balanceOf(RECEIVER) >= timelockRethBalanceBefore + minBuyLimit(),
            "TWAP dao buy token balance is incorrect"
        );
        assertTrue(
            SELL_TOKEN.balanceOf(bob.addr) == counterPartyWstEthBalanceBefore + tradeSize(),
            "Counter Party buy token balance is incorrect"
        );
        assertTrue(
            BUY_TOKEN.balanceOf(bob.addr) >= counterPartyRethBalanceBefore - minBuyLimit(),
            "Counter Party sell token balance is incorrect"
        );
    }

    function testTWAP_FromTimelockPerspective() public {
        require(NUM_PARTS < tradeSize());

        (bytes memory initializer, address STAGING_SAFE) = getSafe(RECEIVER, SALT_NONCE);

        // Do everything from the timelock
        vm.startPrank(address(timelock));

        // Calculate how much stETH we need to wrap to get 500 wstETH
        uint256 stETHAmount = IWstETH(wstETH).getStETHByWstETH(tradeSize());

        // 1. Approve the required amount of stETH required to wrap into wstETH
        stETH.approve(wstETH, stETHAmount);

        // 2. Wrap stETH into wstETH
        IWstETH(wstETH).wrap(stETHAmount);

        // 3. Approve the to-be-created `Safe` contract to use the wstETH
        SELL_TOKEN.approve(STAGING_SAFE, tradeSize());

        // 4. Create the Safe.
        SafeProxy safe = safeFactory.createProxyWithNonce(address(safeSingleton), initializer, uint256(SALT_NONCE));

        assertEq(address(safe), STAGING_SAFE);

        // 5. On the safe, we need to do some configuration:
        //   a. Set `ComposableCoW` as the domain verifier for `GPv2Settlement`
        //   b. Set an allowance for `GPv2VaultRelayer` to use the wstETH
        //   c. Do `transferFrom` of the wstETH to the `Safe` contract
        //   d. Create the TWAP order on `ComposableCoW` via the `Safe` contract

        (address toSafe, uint256 value, string memory signature, bytes memory cd) = configSafe(
            ConfigSafe({
                safe: STAGING_SAFE,
                sellToken: address(SELL_TOKEN),
                sellAmount: tradeSize(),
                source: SOURCE,
                params: getOrder(),
                contextFactory: address(contextFactory),
                contextFactoryPayload: bytes(""),
                postInit: true
            })
        );

        (bool success,) =
            address(toSafe).call{value: value}(abi.encodePacked(bytes4(keccak256(abi.encodePacked(signature))), cd));
        assertEq(success, true);

        // 6. Enforce that the allowance for `wstETH` to be spent from the timelock controller is set back to zero
        SELL_TOKEN.approve(STAGING_SAFE, 0);

        assertEq(SELL_TOKEN.allowance(SOURCE, STAGING_SAFE), 0);
    }

    function testReadyForProd() public pure {
        // 1. Check all TODO comments in the codebase
        // 2. Verify swap rates.
        require(1 == 0, "todo items not fixed");
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

    /**
     * A generic function that takes a `ConfigSafe` struct for post-initialisation configuration of a safe.
     * This uses a multisend function to:
     * 1. Set the domainVerifier for `GPv2Settlement`
     * 2. Set an allowance for `GPv2VaultRelayer` to use the sellToken
     * 3. Do `transferFrom` of the sellToken to the `Safe` contract
     * 4. Create the conditional order on `ComposableCoW` via the `Safe` contract
     * @param config `ConfigSafe` struct containing the post-initialisation configuration for the safe
     * @return to address of the target
     * @return value any value to send
     * @return signature of the call made to the target
     * @return cd calldata to send, with the selector trimmed
     */
    function configSafe(ConfigSafe memory config)
        internal
        view
        returns (address, uint256, string memory, bytes memory)
    {
        bytes memory multisendPayload = abi.encodePacked(
            // 1. Set the domainVerifier for `GPv2Settlement` (if not already set)
            multisendHelper(
                Enum.Operation.Call,
                config.safe,
                0,
                abi.encodeWithSelector(efh.setDomainVerifier.selector, settlement.domainSeparator(), address(ccow))
            ),
            // 2. Set the allowance on wstETH for `GPv2VaultRelayer`
            multisendHelper(
                Enum.Operation.Call,
                address(config.sellToken),
                0,
                abi.encodeWithSelector(IERC20.approve.selector, relayer, config.sellAmount)
            ),
            // 3. Use `transferFrom` to pull funds from the timelock which has already approved the safe
            multisendHelper(
                Enum.Operation.Call,
                address(config.sellToken),
                0,
                abi.encodeWithSelector(IERC20.transferFrom.selector, config.source, config.safe, config.sellAmount)
            ),
            // 4. Create the order
            multisendHelper(
                Enum.Operation.Call,
                address(ccow),
                0,
                abi.encodeWithSelector(
                    ComposableCoW.createWithContext.selector,
                    config.params,
                    IValueFactory(config.contextFactory),
                    config.contextFactoryPayload,
                    true
                )
            )
        );

        return interactionHelper(
            config.safe,
            0,
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            abi.encodeWithSelector(
                Safe.execTransaction.selector,
                address(multisend),
                0,
                abi.encodeWithSelector(MultiSend.multiSend.selector, multisendPayload),
                Enum.Operation.DelegateCall,
                0,
                0,
                0,
                address(0),
                payable(0),
                abi.encodePacked(bytes32(uint256(uint160(address(timelock)))), bytes32(0), bytes1(uint8(1)))
            )
        );
    }

    function tradeSize() internal view returns (uint256) {
        return TOTAL_SELL * (10 ** (IERC20Metadata(wstETH).decimals()));
    }

    function minBuyLimit() internal view returns (uint256) {
        return tradeSize() * TOTAL_BUY_FACTOR / MAX_BPS;
    }

    /**
     * A helper function that takes the target, value, signature and calldata and returns them.
     * As the execution of the call makes use of `abi.encodeWithSignature`, the specified signature
     * is used, and therefore the `calldata` that is passed in as the `cd` parameter to this function
     * needs to have the selector trimmed.
     * @param target of the governor interaction
     * @param value any value to send
     * @param signature of the call made to the target
     * @param cd calldata to send
     * @return to address of the target
     * @return value any value to send
     * @return signature of the call made to the target
     * @return calldata to send, with the selector trimmed
     */
    function interactionHelper(address target, uint256 value, string memory signature, bytes memory cd)
        internal
        pure
        returns (address, uint256, string memory, bytes memory)
    {
        return (
            target,
            value,
            signature,
            BytesLib.slice(cd, 4, cd.length - 4) // trim the selector
        );
    }

    /**
     * A multisend helper to encode the payload for a multisend.
     * @param op Multisend operation, ie. Call, DelegateCall
     * @param to where to call / delegatecall
     * @param value any value to send
     * @param cd calldata to send
     */
    function multisendHelper(Enum.Operation op, address to, uint256 value, bytes memory cd)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint8(op), to, value, cd.length, cd);
    }

    /**
     * Compute the deterministic deployment address of a `Safe` when using `SafeProxyFactory.createProxyWithNonce`.
     * @param initializer for safe that is a component for determining the salt
     * @param saltNonce an additional component for determining the salt
     */
    function computeSafeAddress(bytes memory initializer, bytes32 saltNonce) internal pure returns (address) {
        address from = address(safeFactory);
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), uint256(saltNonce)));
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(safeFactory.proxyCreationCode(), uint256(uint160(address(safeSingleton)))));

        return Create2.computeAddress(salt, initCodeHash, from);
    }

    /**
     * Settle a CoW Protocol Order
     * @dev This generates a counter order and signs it.
     * @param who this order belongs to
     * @param counterParty the account that is on the other side of the trade
     * @param order the order to settle
     * @param bundleBytes the ERC-1271 bundle for the order
     * @param expectedRevertSelector the selector `settle` is expected to revert
     *        with, or `bytes4(0)` if no revert is expected
     */
    function settle(
        address who,
        TestAccount memory counterParty,
        GPv2Order.Data memory order,
        bytes memory bundleBytes,
        bytes4 expectedRevertSelector
    ) internal {
        // Generate counter party's order
        GPv2Order.Data memory counterOrder = GPv2Order.Data({
            sellToken: order.buyToken,
            buyToken: order.sellToken,
            receiver: address(0),
            sellAmount: order.buyAmount,
            buyAmount: order.sellAmount,
            validTo: order.validTo,
            appData: order.appData,
            feeAmount: 0,
            kind: GPv2Order.KIND_BUY,
            partiallyFillable: false,
            buyTokenBalance: GPv2Order.BALANCE_ERC20,
            sellTokenBalance: GPv2Order.BALANCE_ERC20
        });

        bytes memory counterPartySig =
            counterParty.signPacked(GPv2Order.hash(counterOrder, settlement.domainSeparator()));

        // Authorize the GPv2VaultRelayer to spend bob's sell token
        vm.prank(counterParty.addr);
        IERC20(counterOrder.sellToken).approve(address(relayer), counterOrder.sellAmount);

        // first declare the tokens we will be trading
        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(order.sellToken);
        tokens[1] = IERC20(order.buyToken);

        // second declare the clearing prices
        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = counterOrder.sellAmount;
        clearingPrices[1] = counterOrder.buyAmount;

        // third declare the trades
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](2);

        // The safe's order is the first trade
        trades[0] = GPv2Trade.Data({
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            receiver: order.receiver,
            sellAmount: order.sellAmount,
            buyAmount: order.buyAmount,
            validTo: order.validTo,
            appData: order.appData,
            feeAmount: order.feeAmount,
            flags: GPv2TradeEncoder.encodeFlags(order, GPv2Signing.Scheme.Eip1271),
            executedAmount: order.sellAmount,
            signature: abi.encodePacked(who, bundleBytes)
        });

        // Bob's order is the second trade
        trades[1] = GPv2Trade.Data({
            sellTokenIndex: 1,
            buyTokenIndex: 0,
            receiver: address(0),
            sellAmount: counterOrder.sellAmount,
            buyAmount: counterOrder.buyAmount,
            validTo: counterOrder.validTo,
            appData: counterOrder.appData,
            feeAmount: counterOrder.feeAmount,
            flags: GPv2TradeEncoder.encodeFlags(counterOrder, GPv2Signing.Scheme.Eip712),
            executedAmount: counterOrder.sellAmount,
            signature: counterPartySig
        });

        // fourth declare the interactions
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        // finally we can execute the settlement
        vm.prank(solver.addr);
        if (expectedRevertSelector == bytes4(0)) {
            settlement.settle(tokens, clearingPrices, trades, interactions);
        } else {
            vm.expectRevert(expectedRevertSelector);
            settlement.settle(tokens, clearingPrices, trades, interactions);
        }
    }
}
