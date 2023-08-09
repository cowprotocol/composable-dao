// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

import {NounsDAOLogicV2} from "nounsdao/governance/NounsDAOLogicV2.sol";
import {NounsDAOExecutor} from "nounsdao/governance/NounsDAOExecutor.sol";

// NounsDAOExecutor (TimelockController): https://etherscan.io/address/0x0BC3807Ec262cB779b38D65b38158acC3bfedE10#code
// NounsDAOProxy (Governance): https://etherscan.io/address/0x6f3e6272a167e8accb32072d08e0957f9c79223d#code
// NounsDAOLogicV2 (Governance Implementation): https://etherscan.io/address/0x51c7d7c47e440d937208bd987140d6db6b1e4051#code

// Tokens:
// stETH: https://etherscan.io/token/0xae7ab96520de3a18e5e111b5eaab095312d7fe84
// wstETH: https://etherscan.io/token/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0
// rETH: https://etherscan.io/token/0xae78736cd615f374d3085123a210448e74fc6393

contract ProposalTest is Test {

    NounsDAOLogicV2 public dao = NounsDAOLogicV2(payable(0x51C7D7C47E440d937208bD987140D6db6B1E4051));
    NounsDAOExecutor public timelock = NounsDAOExecutor(payable(0x0BC3807Ec262cB779b38D65b38158acC3bfedE10));

    // function setUp() public {
    //     counter = new Counter();
    //     counter.setNumber(0);
    // }

    // function testIncrement() public {
    //     counter.increment();
    //     assertEq(counter.number(), 1);
    // }

    // function testSetNumber(uint256 x) public {
    //     counter.setNumber(x);
    //     assertEq(counter.number(), x);
    // }
}
