from ape import accounts
from ape_accounts import generate_account

# Define required accounts
ACCOUNT_NAMES = ["deployer2", "owner2", "executor"]
DEFAULT_PASSPHRASE = "mySecureP@ssphrase"  # Change this for security

def main():
    for name in ACCOUNT_NAMES:
        if name in accounts.aliases:
            print(f"Account '{name}' already exists.")
        else:
            print(f"Generating account: {name}")
            account, mnemonic = generate_account(name, DEFAULT_PASSPHRASE)
            print(f"Generated {name}: {account.address}")
            print(f"Save your mnemonic: {mnemonic}")

    print("\nAvailable accounts:")
    for alias in accounts.aliases:
        acc = accounts.load(alias)
        print(f" - {alias}: {acc.address}")

if __name__ == "__main__":
    main()
