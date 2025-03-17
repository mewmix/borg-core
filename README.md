```
██████╗  ██████╗ ██████╗  ██████╗     ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔═══██╗██╔══██╗██╔════╝     ██╔═══╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝██║   ██║██████╔╝██║  ███═════██║    ██║   ██║██████╔╝█████╗  
██╔══██╗██║   ██║██╔══██╗██║   ██╔════██║    ██║   ██║██╔══██╗██╔══╝  
██████╔╝╚██████╔╝██║  ██║╚██████╔╝    ██████╗╚██████╔╝██║  ██║███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝  
///The core set of contracts that turn your SAFE cybernetic.
   ╚════╝ ╚═══╝╚═╝  ╚═════╝   ╚═══╝  ╚════╝   ╚═════╝ ╚═╝╚═╝
```

## Overview
These contracts are installed into a Gnosis SAFE multisig to allow the members to operate a BORG to the current BORG RFC Spec. Actions from the SAFE owners will be limited to the scope set forth in the BORG's legal documents and the approval of the adjacent DAO. Configuration of the access control, core policy, and implants are critical when setting up and installing the contracts.

## Components

### BORG Auth / BorgAuthACL `auth.sol`

Multi-permission level access control contract inhereted in all borg contracts. The DAO or an approvaed AuthorityBORG should remain 1 level higher than the BORG members for oversight and controls. Adapatable interface to assign other ACL contracts a role within BORG Auth.

### borg-core `borgCore.sol`
The `borg-core` is the heart of the BORG and houses restricts ALL actions from the SAFE except those whitelisted by the BORG's policy. Granularity down to the parameter level for whitelisting params, methods, and contracts as well as time restriction between actions. Inlcudes on-chain storage for the uri of the BORG's legal docs as well as the adjecent DAO's EIP4824 uri. The borg-core is installed as a Guard contract in the SAFE's guard manager and is managed by the BORG Auth owner(s).

### Condition Manager `conditionManager.sol` / `baseCondition.sol`
A modular contract that enables multiple custom conditions to be met supporting AND/OR logic. Allows conditions to be added on a per-function basis or as per-contract check. Examples include: time, erc20 balance, oracle price, multi-party signatures, oracle injections, erc721/1155 ownership etc.

### GovernanceAdapter `baseGovernanceAdapter.sol`
An adapter to support multiple on chain governance solutions. Implants that interact with on chain governance can optionally include this adapter to automatically set up and/or manage proposals that require direct DAO interaction.

### Implants for a Grants BORG
Implants are Gnosis Modules that grant the BORG access to specific functionality with controls, limitations and oversight for a DAO or Authority BORG. Each one inherits Borg Auth for modular ACL and includes the Condition Manager for conditional logic for each method.

### `optimisticGrantImplant.sol`
This Implant allows grant funds pre-approved by the DAO, with token type, quantity, and time limitations, that BORG members can distrubute.

### `daoVetoGrantImplant.sol`
This Implant allows grant funds that can be distributed after a time period has passed and no veto-action from the DAO. Limited by token type, quantity, and time frequency.

### `daoVoteGrantImplant.sol`
This Implant allows grant funds that can be distributed by a full DAO vote approval.

### `ejectImplant.sol`
This Implant allows a BORG member to remove himself as an owner of the BORG, in the case that he resigns. Limitations include GnosisSafe threshold and conditional checks. This also allows the DAO or Authority address to remove a BORG member from the safe after conditional checks.

### `failSafe.sol`
This Implant allows a DAO treasury address to be set for the recovery of funds in the BORG. Funds can be transferred from the BORG multisig back to the treasury address after conditoinal checks. This may be used in case of the winding down of a BORG, failure/emergency, or a clawback from the DAO.


## Prerequisites

Before you begin, ensure you have the following installed:
- [Node.js](https://nodejs.org/)
- [Foundry](https://book.getfoundry.sh/getting-started/installation.html)
- solc v0.8.20

## Installation

To set up the project locally, follow these steps:

1. **Clone the repository**
   ```bash
   git clone https://github.com/MetaLex-Tech/borg-core
   cd borg-core
   ```
   
2. **Install dependencies**
   ```bash
   foundryup # Update Foundry tools
   forge install # Install project dependencies
   ```
3. **Compile Contracts**

    ```base
    forge build --optimize --optimizer-runs 200 --use solc:0.8.20 --via-ir
    ```

4. **Testing with APE**
 - Setup Ape
    ```base
    pip install eth-ape
   ```
 - Install plugins 
   ```base
    ape plugins install solidity 
   ```
 - Install deps(ape)

   ```base
    ape pm install --force  
   ```
 - Compile 
   ```
   ape compile --force
   ```