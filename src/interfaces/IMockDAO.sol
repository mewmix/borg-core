// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin/contracts/governance/IGovernor.sol";

interface IMockDAO is IGovernor {
    // Extends IGovernor for basic governance functionalities

    // Additional specific functions for MockDAO
    function proposeWithThresholds(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        uint256 quorum,
        uint256 threshold,
        uint256 length
    ) external returns (uint256);

    function getVotes(uint256 proposalId) external view returns (uint256);

    function getSupportVotes(uint256 proposalId) external view returns (uint256);

    // Functions to get the governance parameters
    function quorum(uint256 blockNumber) external view returns (uint256);

    function votingDelay() external view returns (uint256);

    function votingPeriod() external view returns (uint256);
}