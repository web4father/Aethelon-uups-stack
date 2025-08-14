// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./SacredTreasuryUpgradeable.sol"; // The deployed address will be wired

contract Pd4VaultUpgradeable is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    address public pd4Minter;
    SacredTreasuryUpgradeable public sacredTreasury;
    IERC20 public pd4Token;
    uint256 public vaultBalance;
    uint256 public maxTransferPerTx;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _sacredTreasury, address _pd4Token, address _pd4Minter) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        sacredTreasury = SacredTreasuryUpgradeable(_sacredTreasury);
        pd4Token = IERC20(_pd4Token);
        pd4Minter = _pd4Minter;
        maxTransferPerTx = type(uint256).max;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function mintPd4(address to, uint256 amount) public onlyRole(ADMIN_ROLE) {
        require(amount <= maxTransferPerTx, "Transfer amount exceeds cap");
        require(IERC20(pd4Minter).balanceOf(address(this)) >= amount, "Insufficient balance");
        pd4Token.transfer(to, amount);
        vaultBalance += amount;
    }

    function setMaxTransferPerTx(uint256 cap) public onlyRole(ADMIN_ROLE) {
        maxTransferPerTx = cap;
    }

    function getVaultState() public view returns (uint256) {
        return pd4Token.balanceOf(address(this));
    }

    function transferToSacredTreasury(uint256 amount, uint256 contributionId, address user) public onlyRole(ADMIN_ROLE) {
        require(amount <= maxTransferPerTx, "Transfer amount exceeds cap");
        require(vaultBalance >= amount, "Insufficient vault balance");
        vaultBalance -= amount;
        pd4Token.approve(address(sacredTreasury), amount);
        sacredTreasury.provisionTokens(pd4Token, amount, contributionId, user);
    }
}