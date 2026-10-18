import getpass
import sys

import vault


def main():
    print("Veil vault reader. Enter 3 of the 5 shares (input is hidden).")
    hexes = [getpass.getpass(f"Share {i + 1}: ") for i in range(3)]
    try:
        v = vault.Vault.unlock(hexes)
    except (ValueError, IndexError, FileNotFoundError) as e:
        print("Locked:", e)
        sys.exit(1)
    try:
        entries = vault.read_all(v.key)
    except ValueError:
        print("Vault is corrupted or was tampered with.")
        sys.exit(1)
    finally:
        v.close()
    print(f"\nUnlocked. {len(entries)} conversation(s):\n")
    for i, e in enumerate(entries, 1):
        print(f"#{i} [{e['time']}]")
        print("  You:          ", e["real"])
        print("  Provider saw: ", e["provider_saw"])
        print("  Answer:       ", e["answer"])
        print()


if __name__ == "__main__":
    main()
