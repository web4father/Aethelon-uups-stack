// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CovenantVaultUpgradeable is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    mapping(address => bool) public isAethelon;
    uint256 public totalSeals;
    uint256 public maxSeals;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, uint256 _maxSeals) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        maxSeals = _maxSeals;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function joinAethelon(address user) public onlyRole(ADMIN_ROLE) {
        require(!isAethelon[user], "Already in Aethelon");
        require(totalSeals < maxSeals, "Max seals reached");
        isAethelon[user] = true;
        totalSeals++;
    }

    function leaveAethelon(address user) public onlyRole(ADMIN_ROLE) {
        require(isAethelon[user], "Not in Aethelon");
        isAethelon[user] = false;
        totalSeals--;
    }

    function setMaxSeals(uint256 newMaxSeals) public onlyRole(ADMIN_ROLE) {
        maxSeals = newMaxSeals;
    }
}