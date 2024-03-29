// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/ISafe.sol";
import "../libs/auth.sol";
import "../interfaces/ICondition.sol";

contract GrantMilestones is GlobalACL {
    address public immutable BORG_SAFE;

    struct Milestone {
        address token;
        uint256 tokensToUnlock;
        address[] conditionContracts;
        bool isAchieved;
    }

    Milestone[] public milestones;

    constructor(Auth _auth, address _borgSafe) GlobalACL(_auth) {
        BORG_SAFE = _borgSafe;
    }

    modifier onlyBorgSafe() {
        require(BORG_SAFE == msg.sender, "Caller is not the BORG");
        _;
    }

    function addMilestone(address _token, uint256 _tokensToUnlock, address[] memory _conditionContracts) external onlyOwner {
        milestones.push(Milestone(_token, _tokensToUnlock, _conditionContracts, false));
    }

    function removeMilestone(uint256 _milestoneIndex) external onlyOwner {
        require(_milestoneIndex < milestones.length, "Invalid milestone index");
        milestones[_milestoneIndex] = milestones[milestones.length - 1];
        milestones.pop();
    }

    function checkAndUnlockMilestone(uint256 _milestoneIndex) external {
        require(_milestoneIndex < milestones.length, "Invalid milestone index");
        Milestone storage milestone = milestones[_milestoneIndex];

        require(!milestone.isAchieved, "Milestone already achieved");
        for(uint256 i = 0; i < milestone.conditionContracts.length; i++)
            require(ICondition(milestone.conditionContracts[i]).checkCondition(), "Milestone condition not satisfied");

        milestone.isAchieved = true;

        // Execute the token transfer based on the milestone specifics
        if(milestone.token == address(0)) { // native currency transfer
            ISafe(BORG_SAFE).execTransactionFromModule(msg.sender, milestone.tokensToUnlock, "", Enum.Operation.Call);
        } else { // ERC20 token transfer
            ISafe(BORG_SAFE).execTransactionFromModule(milestone.token, 0, abi.encodeWithSignature("transfer(address,uint256)", msg.sender, milestone.tokensToUnlock), Enum.Operation.Call);
        }
    }

}