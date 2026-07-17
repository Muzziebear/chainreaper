// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title MiniVault — a deliberately vulnerable ERC4626-style share vault.
/// @notice BENCHMARK TARGET (not production). It is exposed to the classic
/// first-depositor / donation share-inflation attack: `totalAssets()` reads the
/// raw token balance, and `deposit` mints shares with no virtual offset and no
/// minimum, so an attacker can inflate the share price by donating tokens
/// directly to the vault and make a later victim's deposit round down to ZERO
/// shares — then redeem the inflated pool and walk away with the victim's
/// principal.
contract MiniVault {
    IERC20 public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _asset) {
        asset = _asset;
    }

    /// @dev BUG: pool size = raw token balance → manipulable by a direct donation.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /// @notice Deposit `assets` underlying tokens and mint vault shares to `receiver`.
    /// @dev BUG: no virtual shares / no minimum-shares check, and shares are
    /// computed against the donation-inflatable `totalAssets()`.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : (assets * supply) / totalAssets();
        require(asset.transferFrom(msg.sender, address(this), assets), "transferFrom failed");
        totalSupply = supply + shares;
        balanceOf[receiver] += shares;
    }

    /// @notice Burn `shares` and send the pro-rata underlying to `receiver`.
    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        uint256 supply = totalSupply;
        assets = (shares * totalAssets()) / supply;
        totalSupply = supply - shares;
        balanceOf[msg.sender] -= shares;
        require(asset.transfer(receiver, assets), "transfer failed");
    }
}
