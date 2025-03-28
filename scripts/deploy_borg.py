import os
import json
from ape import accounts, project, networks, Contract
from eth_utils import keccak, to_bytes
from eth_account import Account

with open(r"C:\Users\AKlein.APR1\borg-core\scripts\safe-proxy-abi.json") as f:
    SAFE_PROXY_ABI = json.load(f)

IGNOSIS_SAFE_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_owners", "type": "address[]"},
            {"name": "_threshold", "type": "uint256"},
            {"name": "to", "type": "address"},
            {"name": "data", "type": "bytes"},
            {"name": "fallbackHandler", "type": "address"},
            {"name": "paymentToken", "type": "address"},
            {"name": "payment", "type": "uint256"},
            {"name": "paymentReceiver", "type": "address"}
        ],
        "name": "setup",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "nonce",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "module", "type": "address"}],
        "name": "enableModule",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "guard", "type": "address"}],
        "name": "setGuard",
        "outputs": [],
        "stateMutability": "nonpayable",
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
        "stateMutability": "payable",
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
        "stateMutability": "view",
        "type": "function"
    }
]

SAFE_FACTORY = "0xC22834581EbC8527d974F8a1c97E1bEA4EF910BC"
SAFE_SINGLETON = "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552"
WETH = "0x4200000000000000000000000000000000000006"

def main():
    deployer = accounts.load("deployer3")
    owner2 = accounts.load("owner3")
    executor = accounts.load("executor")
    owner1 = deployer

    print(f"Deployer/Owner1: {deployer.address}")
    print(f"Owner2: {owner2.address}")
    print(f"Executor: {executor.address}")

    with networks.parse_network_choice("base:local") as provider:

        factory = Contract(SAFE_FACTORY, abi=SAFE_PROXY_ABI)
        safe_template = Contract(SAFE_SINGLETON, abi=IGNOSIS_SAFE_ABI)

        owners = [owner1.address, owner2.address]
        threshold = 1
        initializer = safe_template.setup.encode_input(
        owners,
        threshold,
        "0x0000000000000000000000000000000000000000",
        b"",
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
        0,
        "0x0000000000000000000000000000000000000000"
    )

        salt_nonce = 0
        safe_proxy = factory.createProxyWithNonce(
        SAFE_SINGLETON, initializer, salt_nonce,
        sender=deployer,
        gas=300_000
    ).return_value


        safe = Contract(safe_proxy, abi=IGNOSIS_SAFE_ABI)
        print(f"Gnosis Safe deployed at: {safe.address}")

        auth = project.BorgAuth.deploy(sender=deployer)
        print(f"BorgAuth deployed at: {auth.address}")

        core = project.borgCore.deploy(
            auth.address, 0x3, 0, "Submission Dev BORG", safe.address, sender=deployer
        )
        print(f"borgCore deployed at: {core.address}")

        helper = project.SignatureHelper.deploy(sender=deployer)
        core.setSignatureHelper(helper.address, sender=deployer)
        print(f"SignatureHelper set at: {helper.address}")

        fail_safe = project.failSafeImplant.deploy(
            auth.address, safe.address, executor.address, sender=deployer
        )
        enable_module_data = safe.enableModule.encode_input(fail_safe.address)
        execute_safe_tx(safe, deployer, safe.address, 0, enable_module_data)
        print(f"failSafeImplant deployed and enabled at: {fail_safe.address}")

        set_guard_data = safe.setGuard.encode_input(core.address)
        execute_safe_tx(safe, deployer, safe.address, 0, set_guard_data)
        print(f"borgCore set as guard at: {core.address}")

        configure_weth_constraints(core, deployer, WETH, owner2.address)

        auth.updateRole(executor.address, 99, sender=deployer)
        auth.zeroOwner(sender=deployer)
        print(f"BorgAuth ownership transferred to executor: {executor.address}")

def execute_safe_tx(safe, signer, to, value, data):
    nonce = safe.nonce()
    tx_data = safe.encodeTransactionData(
        to, value, data, 0, 0, 0, 0,
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
        nonce
    )
    tx_hash = keccak(to_bytes(hexstr=tx_data.hex()))
    eth_account = Account.from_key(signer.private_key)
    signed = eth_account.sign_message(tx_hash)
    signature = to_bytes(signed.r) + to_bytes(signed.s) + bytes([signed.v])
    safe.execTransaction(
        to, value, data, 0, 0, 0, 0,
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
        signature,
        sender=signer
    )

def configure_weth_constraints(core, deployer, weth, owner2_address):
    owner2_bytes = to_bytes(owner2_address)
    match_hash = keccak(owner2_bytes)

    core.addUnsignedRangeParameterConstraint(
        weth, "approve(address,uint256)", 1, 0, 999999999999999999, 36, 32, sender=deployer
    )
    core.addExactMatchParameterConstraint(
        weth, "approve(address,uint256)", 0, [match_hash], 4, 32, sender=deployer
    )
    core.updateMethodCooldown(weth, "approve(address,uint256)", 604800, sender=deployer)

    core.addUnsignedRangeParameterConstraint(
        weth, "transfer(address,uint256)", 1, 0, 999999999999999999, 36, 32, sender=deployer
    )
    core.addExactMatchParameterConstraint(
        weth, "transfer(address,uint256)", 0, [match_hash], 4, 32, sender=deployer
    )
    core.updateMethodCooldown(weth, "transfer(address,uint256)", 604800, sender=deployer)
    print("WETH constraints configured")

if __name__ == "__main__":
    main()
