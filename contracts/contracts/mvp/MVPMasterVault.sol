// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MVPMasterVault (Partitioned)
 * @notice Covenant vault for Mirror Vault Proxies (MVPs) with per-MVP partitions.
 * @dev 508(c)(1)(A)-aligned: non-redeemable, no member withdrawals, covenantal tithe to Sacred Treasury.
 *      One-way flow: PoP verification → MVPMasterVault (partitioned) → Sacred Treasury.
 *      No ETH accepted. No fallback. No arbitrary external transfers.
 * 
 * Canonical principles encoded:
 *  - MVP creation triggers: DEFICIT or OPPORTUNITY (see createPartition).
 *  - Universal Benefit Clause: >=10% outward tithe auto-routed to Sacred Treasury on every deposit.
 *  - PoP Accounting Mandate: tag source of value (INTERNAL, EXTERNAL) + event id; log temp volunteers.
 *  - Anti-Schism: single Sacred Treasury, no per-MVP “local treasuries,” no doctrine/config drift.
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ISacredTreasury {
    /**
     * @dev Notifies Sacred Treasury of inbound covenantal funds routed from an approved vault.
     *      Implementations MUST NOT expose public redemption to members.
     */
    function notifyInbound(address token, uint256 amount, uint256 mvpId, bytes32 reason) external;
}

contract MVPMasterVault is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    // ---- Roles (canon v.2025-08-11) ---------------------------------------------------------
    bytes32 public constant STEWARD_ROLE     = keccak256("STEWARD_ROLE");     // configure partitions, tokens, params
    bytes32 public constant PROVISIONER_ROLE = keccak256("PROVISIONER_ROLE"); // pull funds (with allowance) + sweep to Treasury
    bytes32 public constant PAUSER_ROLE      = keccak256("PAUSER_ROLE");      // emergency pause/unpause
    bytes32 public constant UPGRADER_ROLE    = keccak256("UPGRADER_ROLE");    // UUPS upgrade gate
    bytes32 public constant ROUTER_ROLE      = keccak256("ROUTER_ROLE");      // Pd4d or approved router to log PoP / deposit

    // ---- Canon constants --------------------------------------------------------------------
    enum MVPMode { DEFICIT, OPPORTUNITY }        // Creation triggers
    enum SourceTag { INTERNAL, EXTERNAL }        // Funding provenance for PoP accounting

    // Treasury + token allowlist
    address public sacredTreasury;
    mapping(address => bool) public acceptedToken;

    // Universal minimum outward tithe (bps). Must be >= 1000 (10%).
    uint16 public minimumOutwardBps; // e.g., 1000 = 10%

    // Per-partition config + accounting
    struct PartitionMeta {
        bool exists;
        MVPMode mode;
        uint16 outwardBps;           // >= minimumOutwardBps
        string regionLabel;          // human-readable operational/relational radius
        bool active;
    }

    // Accounting by partition and token
    mapping(uint256 => PartitionMeta) private _meta;                         // mvpId => meta
    mapping(uint256 => mapping(address => uint256)) private _balances;       // mvpId => token => retained balance (after tithe)
    mapping(uint256 => mapping(address => uint256)) private _totalIn;        // mvpId => token => gross in
    mapping(uint256 => mapping(address => uint256)) private _totalRouted;    // mvpId => token => total routed to Treasury (incl. auto 10% + sweeps)

    // ---- Events -----------------------------------------------------------------------------
    event PartitionCreated(uint256 indexed mvpId, MVPMode mode, uint16 outwardBps, string regionLabel);
    event PartitionStatus(uint256 indexed mvpId, bool active);
    event TokenAllowlist(address indexed token, bool accepted);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event MinimumOutwardBpsUpdated(uint16 oldBps, uint16 newBps);

    event DepositRecorded(
        uint256 indexed mvpId,
        address indexed token,
        address indexed from,
        uint256 grossAmount,
        uint256 titheAmount,
        uint256 retainedAmount,
        SourceTag sourceTag,
        bytes32 eventId
    );

    event PoPVolunteerLogged(uint256 indexed mvpId, bytes32 eventId, bytes32 detailsHash);
    event SweptToTreasury(uint256 indexed mvpId, address indexed token, uint256 amount, bytes32 reason);

    // ---- Modifiers & guards ----------------------------------------------------------------
    modifier partitionExists(uint256 mvpId) {
        require(_meta[mvpId].exists, "MVP partition missing");
        _;
    }

    // ---- Initialize / UUPS ------------------------------------------------------------------
    function initialize(address admin, address _sacredTreasury) public initializer {
        require(admin != address(0), "admin req");
        require(_sacredTreasury != address(0), "treasury req");

        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(STEWARD_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(PROVISIONER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        sacredTreasury = _sacredTreasury;
        minimumOutwardBps = 1000; // 10% canonical floor
        emit TreasuryUpdated(address(0), _sacredTreasury);
        emit MinimumOutwardBpsUpdated(0, minimumOutwardBps);
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    // ---- Canon config ----------------------------------------------------------------------
    function setTreasury(address newTreasury) external onlyRole(STEWARD_ROLE) {
        require(newTreasury != address(0), "treasury=0");
        emit TreasuryUpdated(sacredTreasury, newTreasury);
        sacredTreasury = newTreasury;
    }

    function setMinimumOutwardBps(uint16 newBps) external onlyRole(STEWARD_ROLE) {
        require(newBps >= 1000 && newBps <= 5000, "bps out of canon");
        emit MinimumOutwardBpsUpdated(minimumOutwardBps, newBps);
        minimumOutwardBps = newBps;
    }

    function allowToken(address token, bool ok) external onlyRole(STEWARD_ROLE) {
        acceptedToken[token] = ok;
        emit TokenAllowlist(token, ok);
    }

    function createPartition(
        uint256 mvpId,
        MVPMode mode,
        uint16 outwardBps,
        string calldata regionLabel
    ) external onlyRole(STEWARD_ROLE) {
        require(!_meta[mvpId].exists, "partition exists");
        require(outwardBps >= minimumOutwardBps && outwardBps <= 10000, "bps bounds");
        _meta[mvpId] = PartitionMeta({
            exists: true,
            mode: mode,
            outwardBps: outwardBps,
            regionLabel: regionLabel,
            active: true
        });
        emit PartitionCreated(mvpId, mode, outwardBps, regionLabel);
        emit PartitionStatus(mvpId, true);
    }

    function setPartitionActive(uint256 mvpId, bool active) external onlyRole(STEWARD_ROLE) partitionExists(mvpId) {
        _meta[mvpId].active = active;
        emit PartitionStatus(mvpId, active);
    }

    function setPartitionOutwardBps(uint256 mvpId, uint16 outwardBps)
        external
        onlyRole(STEWARD_ROLE)
        partitionExists(mvpId)
    {
        require(outwardBps >= minimumOutwardBps && outwardBps <= 10000, "bps bounds");
        _meta[mvpId].outwardBps = outwardBps;
    }

    // ---- PoP & deposit paths (pull-with-allowance; no unsolicited transfers) ---------------
    /**
     * @notice Record a deposit for an MVP partition and pull tokens from `from` (must approve first).
     * @dev Only PROVISIONER (stewards) or ROUTER (Pd4d) may call. Auto-routes outward tithe to Sacred Treasury.
     * @param mvpId Partition id.
     * @param token Accepted ERC20 token address.
     * @param from  Source address holding tokens (has approved this contract).
     * @param amount Gross amount to pull.
     * @param sourceTag INTERNAL (covenantal) or EXTERNAL (outside grant/donor).
     * @param eventId  Event/mission identifier (Seal linkage).
     */
    function recordAndPull(
        uint256 mvpId,
        address token,
        address from,
        uint256 amount,
        SourceTag sourceTag,
        bytes32 eventId
    )
        external
        nonReentrant
        whenNotPaused
        partitionExists(mvpId)
    {
        require(hasRole(PROVISIONER_ROLE, _msgSender()) || hasRole(ROUTER_ROLE, _msgSender()), "not authorized");
        require(_meta[mvpId].active, "partition inactive");
        require(acceptedToken[token], "token not allowed");
        require(amount > 0, "amount=0");

        uint16 bps = _meta[mvpId].outwardBps;
        uint256 tithe = (amount * bps) / 10000;
        uint256 retain = amount - tithe;

        // Pull full amount from source into this vault
        IERC20(token).safeTransferFrom(from, address(this), amount);

        // Auto-route tithe to Sacred Treasury
        if (tithe > 0) {
            IERC20(token).safeTransfer(sacredTreasury, tithe);
            _totalRouted[mvpId][token] += tithe;
            ISacredTreasury(sacredTreasury).notifyInbound(token, tithe, mvpId, bytes32("MVP_TITHE"));
            emit SweptToTreasury(mvpId, token, tithe, bytes32("AUTO_TITHE"));
        }

        // Retain remainder inside partition until steward sweeps (canonical one-way flow retained → Treasury)
        _balances[mvpId][token] += retain;
        _totalIn[mvpId][token] += amount;

        emit DepositRecorded(mvpId, token, from, amount, tithe, retain, sourceTag, eventId);
    }

    /**
     * @notice Log a PoP contribution by temporary volunteers (no funds moved), linked to an event.
     * @dev Only Pd4d (ROUTER_ROLE). Off-chain indexers can attribute Honor/Seals via this emission.
     */
    function logVolunteerPoP(
        uint256 mvpId,
        bytes32 eventId,
        bytes32 detailsHash
    )
        external
        whenNotPaused
        partitionExists(mvpId)
        onlyRole(ROUTER_ROLE)
    {
        require(_meta[mvpId].active, "partition inactive");
        emit PoPVolunteerLogged(mvpId, eventId, detailsHash);
    }

    /**
     * @notice Steward/Provisioner can sweep retained partition balances to Sacred Treasury (one-way).
     */
    function sweepToTreasury(
        uint256 mvpId,
        address token,
        uint256 amount,
        bytes32 reason
    )
        external
        nonReentrant
        whenNotPaused
        partitionExists(mvpId)
        onlyRole(PROVISIONER_ROLE)
    {
        require(acceptedToken[token], "token not allowed");
        uint256 bal = _balances[mvpId][token];
        require(amount > 0 && amount <= bal, "insufficient retained");
        _balances[mvpId][token] = bal - amount;

        IERC20(token).safeTransfer(sacredTreasury, amount);
        _totalRouted[mvpId][token] += amount;

        ISacredTreasury(sacredTreasury).notifyInbound(token, amount, mvpId, reason);
        emit SweptToTreasury(mvpId, token, amount, reason);
    }

    // ---- Views ------------------------------------------------------------------------------
    function partitionMeta(uint256 mvpId) external view returns (PartitionMeta memory) {
        return _meta[mvpId];
    }

    function retainedBalance(uint256 mvpId, address token) external view returns (uint256) {
        return _balances[mvpId][token];
    }

    function totals(uint256 mvpId, address token) external view returns (uint256 grossIn, uint256 totalToTreasury) {
        return (_totalIn[mvpId][token], _totalRouted[mvpId][token]);
    }

    // ---- Pause / Safety --------------------------------------------------------------------
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // ---- ETH & fallback hard guards --------------------------------------------------------
    receive() external payable { revert("NO_ETH"); }
    fallback() external payable { revert("NO_FALLBACK"); }
}
