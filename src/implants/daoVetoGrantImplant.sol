// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.20;

import "../interfaces/ISafe.sol";
import "../libs/auth.sol";
import "forge-std/interfaces/IERC20.sol";
import "../interfaces/IGovernanceAdapter.sol";
import "metavest/MetaVesTController.sol";
import "./baseImplant.sol";

/// @title daoVetoGrantImplan
/// @notice This implant allows the BORG to grant time locked grants, vetoable by the DAO or authority.
contract daoVetoGrantImplant is BaseImplant { //is baseImplant

    // BORG Implant ID
    uint256 public immutable IMPLANT_ID = 3;

    // Governance Vars
    uint256 public lastMotionId;
    address public governanceAdapter;
    address public governanceExecutor;

    // MetaVest Vars
    MetaVesT public metaVesT;
    MetaVesTController public metaVesTController;

    // Proposal Vars
    uint256 public duration = 3; //3 days
    uint256 public quorum = 3; //3%
    uint256 public threshold = 25; //25%
    uint256 public waitingPeriod = 24 hours;
    uint256 public lastProposalTime;
    bool public requireBorgVote = true;

    // Grant Proposal Struct
    struct Proposal {
        uint256 id;
        uint256 duration;
        uint256 startTime;
        bytes cdata;
    }

    // Veto Governance Proposal Struct
    struct prop {
        address[] targets;
        uint256[] values;
        bytes[] proposalBytecodes;
        bytes32 desc;
    }

    // Errors and Events
    error daoVetoGrantImplant_NotAuthorized();
    error daoVetoGrantImplant_CallerNotBORGMember();
    error daoVetoGrantImplant_CallerNotBORG();
    error daoVetoGrantImplant_GrantSpendingLimitReached();
    error daoVetoGrantImplant_CallerNotGovernance();
    error daoVetoGrantImplant_InvalidToken();
    error daoVetoGrantImplant_ProposalWaitingPeriodActive();
    error daoVetoGrantImplant_ProposalNotReady();
    error daoVetoGrantImplant_ProposalExecutionError();
    error daoVetoGrantImplant_ProposalNotFound();
    error daoVetoGrantImplant_ApprovalFailed();
    error daoVetoGrantImplant_GrantFailed();

    event GrantTokenAdded(address indexed token, uint256 spendingLimit);
    event GrantTokenRemoved(address indexed token);
    event WaitingPeriodUpdated(uint256 newWaitingPeriod);
    event DurationUpdated(uint256 newDuration);
    event QuorumUpdated(uint256 newQuorum);
    event ThresholdUpdated(uint256 newThreshold);
    event GovernanceAdapterSet(address indexed governanceAdapter);
    event BorgVoteToggled(bool requireBorgVote);
    event DirectGrantProposed(address indexed token, address indexed recipient, uint256 amount, uint256 proposalId, uint256 vetoPropId);
    event SimpleGrantProposed(address indexed token, address indexed recipient, uint256 amount, uint256 proposalId, uint256 vetoPropId);
    event AdvancedGrantProposed(MetaVesT.MetaVesTDetails metavestDetails, uint256 proposalId, uint256 vetoPropId);
    event ProposalExecuted(uint256 proposalId);

    Proposal[] public currentProposals;
    mapping(uint256 => prop) public vetoProposals;
    mapping(uint256 => uint256) internal proposalIndicesByProposalId;
    mapping(address => uint256) approvedGrantTokens;
    uint256 internal constant PERC_SCALE = 10000;

    constructor(BorgAuth _auth, address _borgSafe, uint256 _duration, uint _quorum, uint256 _threshold, uint _waitingPeriod, address _governanceAdapter, address _governanceExecutor,address _metaVestController) BaseImplant(_auth, _borgSafe) {
        duration = _duration;
        quorum = _quorum;
        threshold = _threshold;
        waitingPeriod = _waitingPeriod;
        lastMotionId=0;
        governanceAdapter = _governanceAdapter;
        governanceExecutor = _governanceExecutor;
        metaVesTController = MetaVesTController(_metaVestController);
        metaVesT = MetaVesT(metaVesTController.metavest());
    }

    function addApprovedGrantToken(address _token, uint256 _spendingLimit) external onlyOwner {
        approvedGrantTokens[_token] = _spendingLimit;
        emit GrantTokenAdded(_token, _spendingLimit);
    }

    function removeApprovedGrantToken(address _token) external onlyOwner {
        approvedGrantTokens[_token] = 0;
        emit GrantTokenRemoved(_token);
    }

    function updateWaitingPeriod(uint256 _waitingPeriod) external onlyOwner {
        waitingPeriod = _waitingPeriod;
        emit WaitingPeriodUpdated(_waitingPeriod);
    }

    function updateDuration(uint256 _duration) external onlyOwner {
        duration = _duration;
        emit DurationUpdated(_duration);
    }

    function updateQuorum(uint256 _quorum) external onlyOwner {
        quorum = _quorum;
        emit QuorumUpdated(_quorum);
    }

    function updateThreshold(uint256 _threshold) external onlyOwner {
         threshold = _threshold;
        emit ThresholdUpdated(_threshold);
    }

    function setGovernanceAdapter(address _governanceAdapter) external onlyOwner {
        governanceAdapter = _governanceAdapter;
        emit GovernanceAdapterSet(_governanceAdapter);
    }

    function toggleBorgVote(bool _requireBorgVote) external onlyOwner {
        requireBorgVote = _requireBorgVote;
        emit BorgVoteToggled(_requireBorgVote);
    }

    // should only be executed by a BORG owner/member
    function executeProposal(uint256 _proposalId)
        external
    {
        if(!ISafe(BORG_SAFE).isOwner(msg.sender))
            revert daoVetoGrantImplant_CallerNotBORGMember();

        Proposal storage proposal = _getProposal(_proposalId);

        if(proposal.startTime + proposal.duration > block.timestamp)
            revert daoVetoGrantImplant_ProposalNotReady();

        (bool success,) = address(this).call(proposal.cdata);
        if(!success)
            revert daoVetoGrantImplant_ProposalExecutionError();
        _deleteProposal(_proposalId);
        emit ProposalExecuted(_proposalId);
    }

    function _getProposal(uint256 _proposalId) internal view returns (Proposal storage) {
        uint256 proposalIndex = proposalIndicesByProposalId[_proposalId];
        if(proposalIndex == 0) revert daoVetoGrantImplant_ProposalNotFound();
        return currentProposals[proposalIndex - 1];
    }

    function _deleteProposal(uint256 _proposalId) internal {
        uint256 proposalIndex = proposalIndicesByProposalId[_proposalId];
        if(proposalIndex == 0) revert daoVetoGrantImplant_ProposalNotFound();
        uint256 lastProposalIndex = currentProposals.length - 1;
        if (proposalIndex != lastProposalIndex) {
            currentProposals[proposalIndex - 1] = currentProposals[lastProposalIndex];
            proposalIndicesByProposalId[currentProposals[lastProposalIndex].id] = proposalIndex;
        }
        currentProposals.pop();
        delete proposalIndicesByProposalId[_proposalId];
    }

    function proposeDirectGrant(address _token, address _recipient, uint256 _amount, string memory _desc) external returns (uint256 vetoProposalId, uint256 newProposalId) {
        //Set ID to 0 incase there is a failure in the GovernanceAdapter
        vetoProposalId = 0;
        newProposalId = 0;

        if(lastProposalTime + waitingPeriod > block.timestamp)
            revert daoVetoGrantImplant_ProposalWaitingPeriodActive();

        if(IERC20(_token).balanceOf(address(BORG_SAFE)) < _amount || approvedGrantTokens[_token] < _amount)
            revert daoVetoGrantImplant_GrantSpendingLimitReached();

        if(requireBorgVote) {
            if(BORG_SAFE != msg.sender)
                revert daoVetoGrantImplant_CallerNotBORG();
        }
        else if (BORG_SAFE != msg.sender) {
            if(!ISafe(BORG_SAFE).isOwner(msg.sender))
                revert daoVetoGrantImplant_CallerNotBORGMember();
        }

        bytes memory proposalBytecode = abi.encodeWithSignature("executeDirectGrant(address,address,uint256)", _token, _recipient, _amount);
       
        Proposal storage newProposal = currentProposals.push();
        newProposalId = ++lastMotionId;
        newProposal.id = newProposalId;
        newProposal.startTime = block.timestamp;
        newProposal.cdata = proposalBytecode;
        proposalIndicesByProposalId[newProposalId] = currentProposals.length;

        bytes memory vetoBytecode = abi.encodeWithSignature("_deleteProposal(uint256)", newProposalId);
        address[] memory targets = new address[](1);
        targets[0] = address(this);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory vetoBytecodes = new bytes[](1);
        vetoBytecodes[0] = vetoBytecode;

        if(governanceAdapter != address(0))
        {
            vetoProposalId = IGovernanceAdapter(governanceAdapter).createProposal(targets, values, vetoBytecodes, _desc, quorum, threshold, duration);
            vetoProposals[vetoProposalId] = prop(targets, values, vetoBytecodes, keccak256(abi.encodePacked(_desc)));
        }
       lastProposalTime = block.timestamp;
       emit DirectGrantProposed(_token, _recipient, _amount, newProposalId, vetoProposalId);
    }

    function proposeSimpleGrant(address _token, address _recipient, uint256 _amount, string memory _desc) external returns (uint256 vetoProposalId, uint256 newProposalId) {
        vetoProposalId = 0;
        newProposalId = 0;

        if(lastProposalTime + waitingPeriod > block.timestamp)
            revert daoVetoGrantImplant_ProposalWaitingPeriodActive();

        if(IERC20(_token).balanceOf(address(BORG_SAFE)) < _amount || approvedGrantTokens[_token] < _amount)
            revert daoVetoGrantImplant_GrantSpendingLimitReached();

        if(requireBorgVote) {
            if(BORG_SAFE != msg.sender)
                revert daoVetoGrantImplant_CallerNotBORG();
        }
        else if (BORG_SAFE != msg.sender) {
            if(!ISafe(BORG_SAFE).isOwner(msg.sender))
                revert daoVetoGrantImplant_CallerNotBORGMember();
        }

        bytes memory proposalBytecode = abi.encodeWithSignature("executeSimpleGrant(address,address,uint256)", _token, _recipient, _amount);
     
        Proposal storage newProposal = currentProposals.push();
        newProposalId = ++lastMotionId;
        newProposal.id = newProposalId;
        newProposal.startTime = block.timestamp;
        newProposal.cdata = proposalBytecode;
        proposalIndicesByProposalId[newProposalId] = currentProposals.length;

        bytes memory vetoBytecode = abi.encodeWithSignature("_deleteProposal(uint256)", newProposalId);
        address[] memory targets = new address[](1);
        targets[0] = address(this);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory vetoBytecodes = new bytes[](1);
        vetoBytecodes[0] = vetoBytecode;

        if(governanceAdapter != address(0))
        {
            vetoProposalId = IGovernanceAdapter(governanceAdapter).createProposal(targets, values, vetoBytecodes, _desc, quorum, threshold, duration);
            vetoProposals[vetoProposalId] = prop(targets, values, vetoBytecodes, keccak256(abi.encodePacked(_desc)));
        }

        lastProposalTime = block.timestamp;
        emit SimpleGrantProposed(_token, _recipient, _amount, newProposalId, vetoProposalId);
    }

    function proposeAdvancedGrant(MetaVesT.MetaVesTDetails calldata _metaVestDetails, string memory _desc) external returns (uint256 vetoProposalId, uint256 newProposalId) {
        vetoProposalId = 0;
        newProposalId = 0;
        
        if(lastProposalTime + waitingPeriod > block.timestamp)
            revert daoVetoGrantImplant_ProposalWaitingPeriodActive();

        uint256 _milestoneTotal;
        for (uint256 i; i < _metaVestDetails.milestones.length; ++i) {
            _milestoneTotal += _metaVestDetails.milestones[i].milestoneAward;
        }
        uint256 _total = _metaVestDetails.allocation.tokenStreamTotal +
            _milestoneTotal;

        if(IERC20(_metaVestDetails.allocation.tokenContract).balanceOf(address(BORG_SAFE)) < _total || approvedGrantTokens[_metaVestDetails.allocation.tokenContract] < _total)
            revert daoVetoGrantImplant_GrantSpendingLimitReached();

        if(requireBorgVote) {
            if(BORG_SAFE != msg.sender)
                revert daoVetoGrantImplant_CallerNotBORG();
        }
        else if (BORG_SAFE != msg.sender) {
            if(!ISafe(BORG_SAFE).isOwner(msg.sender))
                revert daoVetoGrantImplant_CallerNotBORGMember();
        }

        bytes memory proposalBytecode = abi.encodeWithSignature("executeAdvancedGrant(MetaVesT.MetaVesTDetails)", _metaVestDetails);

        Proposal storage newProposal = currentProposals.push();
        newProposalId = ++lastMotionId;
        newProposal.id = newProposalId;
        newProposal.startTime = block.timestamp;
        newProposal.cdata = proposalBytecode;
        proposalIndicesByProposalId[newProposalId] = currentProposals.length;

        bytes memory vetoBytecode = abi.encodeWithSignature("_deleteProposal(uint256)", newProposalId);
        address[] memory targets = new address[](1);
        targets[0] = address(this);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory vetoBytecodes = new bytes[](1);
        vetoBytecodes[0] = vetoBytecode;

        if(governanceAdapter != address(0))
        {
            vetoProposalId = IGovernanceAdapter(governanceAdapter).createProposal(targets, values, vetoBytecodes, _desc, quorum, threshold, duration);
            vetoProposals[vetoProposalId] = prop(targets, values, vetoBytecodes, keccak256(abi.encodePacked(_desc)));
        }

        lastProposalTime = block.timestamp;
        emit AdvancedGrantProposed(_metaVestDetails, newProposalId, vetoProposalId);
    }

    function executeDirectGrant(address _token, address _recipient, uint256 _amount) internal {

        if(IERC20(_token).balanceOf(address(BORG_SAFE)) < _amount)
            revert daoVetoGrantImplant_GrantSpendingLimitReached();

        if(_token==address(0))
            ISafe(BORG_SAFE).execTransactionFromModule(_recipient, _amount, "", Enum.Operation.Call);
        else
            ISafe(BORG_SAFE).execTransactionFromModule(_token, 0, abi.encodeWithSignature("transfer(address,uint256)", _recipient, _amount), Enum.Operation.Call);
    }

    function executeSimpleGrant(address _token, address _recipient, uint256 _amount) internal {

        if(IERC20(_token).balanceOf(address(BORG_SAFE)) < _amount)
            revert daoVetoGrantImplant_GrantSpendingLimitReached();

         //Configure the metavest details
        MetaVesT.Milestone[] memory emptyMilestones;
        MetaVesT.MetaVesTDetails memory _metavestDetails = MetaVesT.MetaVesTDetails({
            metavestType: MetaVesT.MetaVesTType.ALLOCATION,
            allocation: MetaVesT.Allocation({
                tokenStreamTotal: _amount,
                tokenGoverningPower: 0,
                tokensVested: 0,
                tokensUnlocked: 0,
                vestedTokensWithdrawn: 0,
                unlockedTokensWithdrawn: 0,
                vestingCliffCredit: uint128(_amount),
                unlockingCliffCredit: uint128(_amount),
                vestingRate: 1,
                vestingStartTime: 0,
                vestingStopTime: 1,
                unlockRate: 1,
                unlockStartTime: 0,
                unlockStopTime: 1,
                tokenContract: _token
            }),
            option: MetaVesT.TokenOption({exercisePrice: 0, tokensForfeited: 0, shortStopTime: uint48(0)}),
            rta: MetaVesT.RestrictedTokenAward({repurchasePrice: 0, tokensRepurchasable: 0, shortStopTime: uint48(0)}),
            eligibleTokens: MetaVesT.GovEligibleTokens({nonwithdrawable: false, vested: true, unlocked: true}),
            grantee: _recipient,
            milestones: emptyMilestones,
            transferable: false
        });

        //approve metaVest to spend the amount
        ISafe(BORG_SAFE).execTransactionFromModule(_token, 0, abi.encodeWithSignature("approve(address,uint256)", address(metaVesT), _amount), Enum.Operation.Call);
        ISafe(BORG_SAFE).execTransactionFromModule(address(metaVesTController), 0, abi.encodeWithSignature("createMetavestAndLockTokens((address,bool,uint8,(uint256,uint256,uint256,uint256,uint256,uint256,uint128,uint128,uint160,uint48,uint48,uint160,uint48,uint48,address),(uint256,uint208,uint48),(uint256,uint208,uint48),(bool,bool,bool),(uint256,bool,address[])[]))", _metavestDetails), Enum.Operation.Call);
  
    }

    function executeAdvancedGrant(MetaVesT.MetaVesTDetails calldata _metavestDetails) internal {

         //cycle through any allocations and approve the metavest to spend the amount
        uint256 _milestoneTotal;
        for (uint256 i; i < _metavestDetails.milestones.length; ++i) {
            _milestoneTotal += _metavestDetails.milestones[i].milestoneAward;
        }
        uint256 _total = _metavestDetails.allocation.tokenStreamTotal +
            _milestoneTotal;

        ISafe(BORG_SAFE).execTransactionFromModule(_metavestDetails.allocation.tokenContract, 0, abi.encodeWithSignature("approve(address,uint256)", address(metaVesT), _total), Enum.Operation.Call);
        ISafe(BORG_SAFE).execTransactionFromModule(address(metaVesTController), 0, abi.encodeWithSignature("createMetavestAndLockTokens((address,bool,uint8,(uint256,uint256,uint256,uint256,uint256,uint256,uint128,uint128,uint160,uint48,uint48,uint160,uint48,uint48,address),(uint256,uint208,uint48),(uint256,uint208,uint48),(bool,bool,bool),(uint256,bool,address[])[]))", _metavestDetails), Enum.Operation.Call);
  
    }
}
