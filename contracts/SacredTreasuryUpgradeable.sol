// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./CovenantVaultUpgradeable.sol";

contract SacredTreasuryUpgradeable is Initializable, AccessControlUpgradeable, UUPSUpgradeable, PausableUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    CovenantVaultUpgradeable public covenantVault;
    address public router;
    uint256 public totalProvisioned;
    uint256 public maxProvisionPerTx;

    mapping(address => bool) public allowedTokens;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, address _covenantVault, address _router) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        covenantVault = CovenantVaultUpgradeable(_covenantVault);
        router = _router;
        maxProvisionPerTx = type(uint256).max;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function setAllowedToken(address token, bool isAllowed) public onlyRole(ADMIN_ROLE) {
        allowedTokens[token] = isAllowed;
    }

    function setRouter(address newRouter) public onlyRole(ADMIN_ROLE) {
        router = newRouter;
    }

    function setMaxProvisionPerTx(uint256 cap) public onlyRole(ADMIN_ROLE) {
        maxProvisionPerTx = cap;
    }

    function pause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function provisionTokens(IERC20 token, uint256 amount, uint256 contributionId, address user) public whenNotPaused {
        require(allowedTokens[address(token)], "Token not allowed");
        require(amount <= maxProvisionPerTx, "Provision amount exceeds cap");
        require(covenantVault.isAethelon(user), "User not in Aethelon");
        
        // This is a simplified treasury logic. In a real project, this is where
        // tokens would be managed, potentially swapped, or held.
        totalProvisioned += amount;
    }
}