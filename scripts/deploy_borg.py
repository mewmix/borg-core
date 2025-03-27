import os
from ape import accounts, project, networks, Contract
from eth_utils import keccak, to_bytes
from eth_account import Account

# Minimal IGnosisSafe ABI (only the methods used in the script)
IGNOSIS_SAFE_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "nonce",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "data", "type": "bytes"},
            {"name": "operation", "type": "uint8"},
            {"name": "safeTxGas", "type": "uint256"},
            {"name": "baseGas", "type": "uint256"},
            {"name": "gasPrice", "type": "uint256"},
            {"name": "gasToken", "type": "address"},
            {"name": "refundReceiver", "type": "address"},
            {"name": "signatures", "type": "bytes"}
        ],
        "name": "execTransaction",
        "outputs": [{"name": "success", "type": "bool"}],
        "payable": True,
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "module", "type": "address"}],
        "name": "enableModule",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "guard", "type": "address"}],
        "name": "setGuard",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "data", "type": "bytes"},
            {"name": "operation", "type": "uint8"},
            {"name": "safeTxGas", "type": "uint256"},
            {"name": "baseGas", "type": "uint256"},
            {"name": "gasPrice", "type": "uint256"},
            {"name": "gasToken", "type": "address"},
            {"name": "refundReceiver", "type": "address"},
            {"name": "nonce", "type": "uint256"}
        ],
        "name": "encodeTransactionData",
        "outputs": [{"name": "", "type": "bytes"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    }
]

# Base Chain Safe deployment addresses
SAFE_FACTORY = "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2"  # SafeProxyFactory on Base
SAFE_SINGLETON = "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552"  # Safe singleton on Base
WETH = "0x4200000000000000000000000000000000000006"  # Base WETH

def main():
    # Load accounts (replace with your account aliases or private keys)
    deployer = accounts.load("deployer2")  # Maps to DEPLOYER_PK
    owner2 = accounts.load("owner2")       # Maps to OWNER2_PK
    executor = accounts.load("executor")   # Maps to EXECUTOR_PK
    owner1 = deployer  # Owner1 is the deployer in this case

    print(f"Deployer/Owner1: {deployer.address}")
    print(f"Owner2: {owner2.address}")
    print(f"Executor: {executor.address}")

    with networks.parse_network_choice("base") as provider:
        # Deploy Gnosis Safe via SafeProxyFactory
        factory = Contract(SAFE_FACTORY)
        owners = [owner1.address, owner2.address]
        threshold = 1
        initializer = project.IGnosisSafe.encode_function_data(
            "setup",
            owners,
            threshold,
            "0x0000000000000000000000000000000000000000",  # to (no module)
            b"",                                                  # data (empty)
            "0x0000000000000000000000000000000000000000",  # fallbackHandler
            "0x0000000000000000000000000000000000000000",  # paymentToken
            0,                                                    # payment
            "0x0000000000000000000000000000000000000000"   # paymentReceiver
        )
        salt_nonce = 0  # Unique salt nonce
        safe_proxy = factory.createProxyWithNonce(
            SAFE_SINGLETON, initializer, salt_nonce, sender=deployer
        ).return_value
        safe = Contract(safe_proxy, abi=IGNOSIS_SAFE_ABI)
        print(f"Gnosis Safe deployed at: {safe.address}")

        # Deploy BorgAuth
        auth = project.BorgAuth.deploy(sender=deployer)
        print(f"BorgAuth deployed at: {auth.address}")

        # Deploy borgCore
        core = project.borgCore.deploy(
            auth.address,          # BorgAuth address
            0x3,                   # borgType
            0,                     # Whitelist mode (borgModes.whitelist)
            "Submission Dev BORG", # Identifier
            safe.address,          # Safe address
            sender=deployer
        )
        print(f"borgCore deployed at: {core.address}")

        # Deploy SignatureHelper and set it
        helper = project.SignatureHelper.deploy(sender=deployer)
        core.setSignatureHelper(helper.address, sender=deployer)
        print(f"SignatureHelper set at: {helper.address}")

        # Deploy failSafeImplant and enable it as a module
        fail_safe = project.failSafeImplant.deploy(
            auth.address,      # BorgAuth address
            safe.address,      # Safe address
            executor.address,  # Executor address
            sender=deployer
        )
        enable_module_data = safe.enableModule.encode_input(fail_safe.address)
        execute_safe_tx(safe, deployer, safe.address, 0, enable_module_data)
        print(f"failSafeImplant deployed and enabled at: {fail_safe.address}")

        # Set borgCore as guard on the Safe
        set_guard_data = safe.setGuard.encode_input(core.address)
        execute_safe_tx(safe, deployer, safe.address, 0, set_guard_data)
        print(f"borgCore set as guard at: {core.address}")

        # Configure WETH constraints
        configure_weth_constraints(core, deployer, WETH, owner2.address)

        # Transfer BorgAuth ownership to executor
        auth.updateRole(executor.address, 99, sender=deployer)
        auth.zeroOwner(sender=deployer)
        print(f"BorgAuth ownership transferred to executor: {executor.address}")

def execute_safe_tx(safe, signer, to, value, data):
    """Execute a transaction on the Safe."""
    nonce = safe.nonce()
    tx_data = safe.encodeTransactionData(
        to,
        value,
        data,
        0,  # Operation (Call)
        0,  # safeTxGas
        0,  # baseGas
        0,  # gasPrice
        "0x0000000000000000000000000000000000000000",  # gasToken
        "0x0000000000000000000000000000000000000000",  # refundReceiver
        nonce
    )
    tx_hash = keccak(to_bytes(hexstr=tx_data.hex()))
    eth_account = Account.from_key(signer.private_key)
    signed = eth_account.sign_message(tx_hash)
    signature = to_bytes(signed.r) + to_bytes(signed.s) + bytes([signed.v])
    safe.execTransaction(
        to,
        value,
        data,
        0,  # Operation
        0,  # safeTxGas
        0,  # baseGas
        0,  # gasPrice
        "0x0000000000000000000000000000000000000000",  # gasToken
        "0x0000000000000000000000000000000000000000",  # refundReceiver
        signature,
        sender=signer
    )

def configure_weth_constraints(core, deployer, weth, owner2_address):
    """Configure WETH approve and transfer constraints."""
    owner2_bytes = to_bytes(owner2_address)
    match_hash = keccak(owner2_bytes)

    # Approve constraints
    core.addUnsignedRangeParameterConstraint(
        weth,
        "approve(address,uint256)",
        1,  # UINT type
        0,
        999999999999999999,  # Max value (< 1 ETH)
        36,                  # Byte offset
        32,                  # Byte length
        sender=deployer
    )
    core.addExactMatchParameterConstraint(
        weth,
        "approve(address,uint256)",
        0,  # ADDRESS type
        [match_hash],
        4,   # Byte offset
        32,  # Byte length
        sender=deployer
    )
    core.updateMethodCooldown(
        weth,
        "approve(address,uint256)",
        604800,  # 7 days in seconds
        sender=deployer
    )

    # Transfer constraints
    core.addUnsignedRangeParameterConstraint(
        weth,
        "transfer(address,uint256)",
        1,  # UINT type
        0,
        999999999999999999,  # Max value (< 1 ETH)
        36,                  # Byte offset
        32,                  # Byte length
        sender=deployer
    )
    core.addExactMatchParameterConstraint(
        weth,
        "transfer(address,uint256)",
        0,  # ADDRESS type
        [match_hash],
        4,   # Byte offset
        32,  # Byte length
        sender=deployer
    )
    core.updateMethodCooldown(
        weth,
        "transfer(address,uint256)",
        604800,  # 7 days in seconds
        sender=deployer
    )
    print("WETH constraints configured")

if __name__ == "__main__":
    main()