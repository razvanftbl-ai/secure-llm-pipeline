import os
import tempfile

import vault

passed = total = 0


def check(name, cond):
    global passed, total
    total += 1
    passed += bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name)


path = os.path.join(tempfile.mkdtemp(), "v.bin")
v, shares = vault.Vault.create(path)
v.append({"real": "My name is John Smith", "answer": "Hello John"})
v.append({"real": "password=Sup3rS3cret", "answer": "ok"})
v.close()

raw = open(path).read()
check("vault file contains no plaintext", "John" not in raw and "Sup3rS3cret" not in raw)

v2 = vault.Vault.unlock([shares[0], shares[2], shares[4]], path)
entries = vault.read_all(v2.key, path)
check("3 shares unlock and decrypt history", len(entries) == 2 and entries[0]["answer"] == "Hello John")
v2.append({"real": "third", "answer": "x"})
check("can append after reopening", len(vault.read_all(v2.key, path)) == 3)
v2.close()

try:
    vault.Vault.unlock([shares[0], shares[1]], path)
    check("2 shares cannot unlock", False)
except ValueError:
    check("2 shares cannot unlock", True)

bad = shares[1][:-2] + ("00" if shares[1][-2:] != "00" else "ff")
try:
    vault.Vault.unlock([shares[0], bad, shares[2]], path)
    check("corrupted share cannot unlock", False)
except ValueError:
    check("corrupted share cannot unlock", True)

# tamper: swap two entries
lines = open(path).read().split("\n")
lines[1], lines[2] = lines[2], lines[1]
open(path, "w").write("\n".join(lines))
v3 = vault.Vault.unlock(shares[:3], path)
try:
    vault.read_all(v3.key, path)
    check("reordered entries detected", False)
except ValueError:
    check("reordered entries detected", True)
v3.close()

print(f"\n{passed}/{total} tests passed")
