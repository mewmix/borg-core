from ape import accounts
from ape_accounts import import_account_from_private_key

# Known Anvil keys (Foundry default)
ANVIL_KEYS = {
    "deployer3": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "owner3":    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "executor3":  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
}

PASSPHRASE = "anvil"  # dummy, required by API but irrelevant for ephemeral use

def main():
    for alias, key in ANVIL_KEYS.items():
        if alias in accounts.aliases:
            print(f"Alias '{alias}' already exists: {accounts.load(alias).address}")
        else:
            account = import_account_from_private_key(alias, PASSPHRASE, key)
            account.set_autosign(True)
            print(f"Imported '{alias}': {account.address}")

if __name__ == "__main__":
    main()
