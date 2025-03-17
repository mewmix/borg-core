# scripts/deploy_borg.py

from ape import accounts, project, networks
from eth_utils import keccak
from eth_account import Account
from eth_utils import to_bytes

def main():
    # Setup network and accounts
    deployer = accounts.load("deployer2")
    owner2 = accounts.load("owner2")
    executor = accounts.load("executor")

    # Constants (Base Chain addresses)
    SAFE_FACTORY = "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2"
    SAFE_SINGLETON = "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552"
    WETH = "0x4200000000000000000000000000000000000006"

    # Derive addresses from test accounts
    print(f"Deployer: {deployer.address}")
    print(f"Owner2: {owner2.address}")
    print(f"Executor: {executor.address}")

    with networks.parse_network_choice("base:mainnet-fork") as provider:

        # Deploy Gnosis Safe
        safe_factory = project.SafeProxyFactory.at(SAFE_FACTORY)
        owners = [deployer.address, owner2.address]
        threshold = 1
        initializer = project.GnosisSafe.encode_input(
            owners,
            threshold,
            "0x0000000000000000000000000000000000000000",
            b"",
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
            0,
            "0x0000000000000000000000000000000000000000"
        )

        # Create Safe proxy
        proxy = safe_factory.createProxyWithNonce(
            SAFE_SINGLETON,
            initializer,
            0,
            sender=deployer
        )
        safe = project.IGnosisSafe.at(proxy.return_value)
        print(f"Gnosis Safe deployed at: {safe.address}")

        # Deploy Borg contracts
        auth = project.BorgAuth.deploy(sender=deployer)
        print(f"BorgAuth deployed at: {auth.address}")

        core = project.borgCore.deploy(
            auth,
            0x3,
            0,  # Whitelist mode
            "Submission Dev BORG",
            safe.address,
            sender=deployer
        )
        print(f"borgCore deployed at: {core.address}")

        helper = project.SignatureHelper.deploy(sender=deployer)
        core.setSignatureHelper(helper.address, sender=deployer)
        print(f"SignatureHelper set at: {helper.address}")

        # Deploy and enable failSafeImplant
        fail_safe = project.failSafeImplant.deploy(
            auth,
            safe.address,
            executor.address,
            sender=deployer
        )
        enable_module_data = safe.enableModule.encode_input(fail_safe.address)
        execute_safe_tx(safe, deployer, safe.address, 0, enable_module_data)
        print(f"failSafeImplant enabled at: {fail_safe.address}")

        # Set borgCore as guard
        set_guard_data = safe.setGuard.encode_input(core.address)
        execute_safe_tx(safe, deployer, safe.address, 0, set_guard_data)
        print(f"borgCore set as guard at: {core.address}")

        # Configure WETH constraints
        configure_weth_constraints(core, deployer, WETH, owner2.address)

        # Transfer auth ownership
        auth.updateRole(executor.address, 99, sender=deployer)
        auth.zeroOwner(sender=deployer)
        print(f"Ownership transferred to executor: {executor.address}")

def execute_safe_tx(safe, signer, to, value, data):
    nonce = safe.nonce()
    tx_data = safe.encode_transaction_data(
        to,
        value,
        data,
        0,  # Operation
        0,  # safeTxGas
        0,  # baseGas
        0,  # gasPrice
        "0x0000000000000000000000000000000000000000",  # gasToken
        "0x0000000000000000000000000000000000000000",  # refundReceiver
        nonce
    )
    
    # Sign with deployer
    tx_hash = keccak(to_bytes(hexstr=tx_data.hex()))

    eth_account = Account.from_key(signer.private_key)
    signed = eth_account.signHash(tx_hash)
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
    # Generate match hash
    owner2_bytes = to_bytes(owner2_address)
    match_hash = keccak(owner2_bytes)
    
    # Approve constraints
    core.addUnsignedRangeParameterConstraint(
        weth,
        "approve(address,uint256)",
        1,  # UINT type
        0,
        999999999999999999,
        36,
        32,
        sender=deployer
    )
    
    core.addExactMatchParameterConstraint(
        weth,
        "approve(address,uint256)",
        0,  # ADDRESS type
        [match_hash],
        4,
        32,
        sender=deployer
    )
    
    core.updateMethodCooldown(
        weth,
        "approve(address,uint256)",
        604800,
        sender=deployer
    )
    
    # Transfer constraints
    core.addUnsignedRangeParameterConstraint(
        weth,
        "transfer(address,uint256)",
        1,  # UINT type
        0,
        999999999999999999,
        36,
        32,
        sender=deployer
    )
    
    core.addExactMatchParameterConstraint(
        weth,
        "transfer(address,uint256)",
        0,  # ADDRESS type
        [match_hash],
        4,
        32,
        sender=deployer
    )
    
    core.updateMethodCooldown(
        weth,
        "transfer(address,uint256)",
        604800,
        sender=deployer
    )
    print("WETH constraints configured")