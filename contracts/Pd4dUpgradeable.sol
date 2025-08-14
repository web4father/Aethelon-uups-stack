// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./CovenantVaultUpgradeable.sol";
import "./OracleStub.sol";

contract Pd4dUpgradeable is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    CovenantVaultUpgradeable public covenantVault;
    OracleStub public oracle;

    mapping(address => mapping(uint256 => bool)) public hasMintedForContribution;
    mapping(address => mapping(uint256 => bool)) public hasAssignedHonorForContribution;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, address _covenantVault, address _oracle) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        covenantVault = CovenantVaultUpgradeable(_covenantVault);
        oracle = OracleStub(_oracle);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function mintTokens(address pd4Vault, uint256 amount, address user, uint256 contributionId, string memory contributionType, uint256 rating) public onlyRole(ADMIN_ROLE) {
        require(covenantVault.isAethelon(user), "User not in Aethelon");
        require(oracle.getRating(user, contributionType) == rating, "Rating mismatch");
        require(!hasMintedForContribution[user][contributionId], "Tokens already minted for this contribution");

        // Mint logic in Pd4Vault
        Pd4VaultUpgradeable(pd4Vault).mintPd4(user, amount);
        hasMintedForContribution[user][contributionId] = true;
    }

    function assignHonor(address user, uint256 amount, uint256 contributionId, string memory contributionType) public onlyRole(ADMIN_ROLE) {
        require(covenantVault.isAethelon(user), "User not in Aethelon");
        require(!hasAssignedHonorForContribution[user][contributionId], "Honor already assigned for this contribution");

        // Honor assignment logic
        hasAssignedHonorForContribution[user][contributionId] = true;
    }
}