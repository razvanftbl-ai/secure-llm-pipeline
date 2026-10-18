import seclib
from masker import Masker

ok = 0
def check(name, cond):
    global ok
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += cond

key = seclib.generate_key()
msg = b"date secrete"

# 1. nonce unic
a = seclib.encrypt(key, msg)
b = seclib.encrypt(key, msg)
check("nonce unic: acelasi text -> ciphertext diferit", a != b and a[:12] != b[:12])

# 2. cheie gresita
try:
    seclib.decrypt(seclib.generate_key(), a)
    check("cheie gresita respinsa", False)
except ValueError:
    check("cheie gresita respinsa", True)

# 3. AAD gresit
blob = seclib.encrypt(key, msg, b"ctx-A")
try:
    seclib.decrypt(key, blob, b"ctx-B")
    check("AAD gresit respins", False)
except ValueError:
    check("AAD gresit respins", True)

# 4. sub prag
shares = seclib.split_secret(key, 3, 5)
check("3 share-uri reconstruiesc cheia", seclib.combine_shares(shares[:3]) == key)
check("2 share-uri NU reconstruiesc cheia", seclib.combine_shares(shares[:2]) != key)

# 5. share duplicat
try:
    seclib.combine_shares([shares[0], shares[0], shares[1]])
    check("share duplicat respins", False)
except ValueError:
    check("share duplicat respins", True)

# 6. nimic sensibil catre provider
secrets = ["Ion Popescu", "ion.popescu@gmail.com", "0712345678",
           "RO49AAAA1B31007593840000", "1960101123456"]
text = "Sunt Ion Popescu, ion.popescu@gmail.com, 0712345678, RO49AAAA1B31007593840000, CNP 1960101123456."
masked = Masker().mask(text)
leaks = [s for s in secrets if s in masked]
check(f"niciun secret in textul trimis la provider (scurgeri: {leaks})", not leaks)

# 7. ciphertext-ul nu contine plaintext
check("ciphertext-ul nu contine plaintext", msg not in a)

print(f"\n{ok} teste trecute")
