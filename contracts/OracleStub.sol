// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract OracleStub is Ownable {
    function getRating(address user, string memory contributionType) public view returns (uint256) {
        // Return a mock rating. In a real oracle, this would be based on
        // attestation or on-chain data.
        return 100;
    }
}