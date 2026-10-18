import seclib
from masker import Masker

passed = 0
total = 0


def check(name, cond):
    global passed, total
    total += 1
    passed += bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name)


key = seclib.generate_key()
msg = b"private data"

# --- Crypto core ---
a = seclib.encrypt(key, msg)
b = seclib.encrypt(key, msg)
check("unique nonce: same plaintext -> different ciphertext", a != b and a[:12] != b[:12])
check("ciphertext does not contain plaintext", msg not in a)

try:
    seclib.decrypt(seclib.generate_key(), a)
    check("wrong key rejected", False)
except ValueError:
    check("wrong key rejected", True)

blob = seclib.encrypt(key, msg, b"ctx-A")
try:
    seclib.decrypt(key, blob, b"ctx-B")
    check("wrong AAD (context) rejected", False)
except ValueError:
    check("wrong AAD (context) rejected", True)

bad = bytearray(blob)
bad[20] ^= 1
try:
    seclib.decrypt(key, bytes(bad), b"ctx-A")
    check("tampered ciphertext rejected", False)
except ValueError:
    check("tampered ciphertext rejected", True)

# --- Shamir ---
shares = seclib.split_secret(key, 3, 5)
check("3 of 5 shares reconstruct the key", seclib.combine_shares(shares[:3]) == key)
check("any 3 shares work", seclib.combine_shares([shares[0], shares[2], shares[4]]) == key)
check("2 shares do NOT reconstruct the key", seclib.combine_shares(shares[:2]) != key)
try:
    seclib.combine_shares([shares[0], shares[0], shares[1]])
    check("duplicate share rejected", False)
except ValueError:
    check("duplicate share rejected", True)

# --- Secret scanner (fake keys built at runtime) ---
secrets = {
    "openai": "sk-" + "proj-" + "abcdEFGH1234" * 4,
    "aws": "AKIA" + "IOSFODNN7EXAMPLE",
    "github": "ghp_" + "a1B2c3D4e5" * 4,
    "password": "Sup3rS3cretPass!",
}
code = (
    f'OPENAI_API_KEY = "{secrets["openai"]}"\n'
    f'aws_key = {secrets["aws"]}\n'
    f'GITHUB = {secrets["github"]}\n'
    f'db_password = "{secrets["password"]}"\n'
)
m = Masker()
masked = m.mask(code)
leaks = [n for n, s in secrets.items() if s in masked]
check(f"no secret leaves the device (leaks: {leaks})", not leaks)
check("secrets are replaced by tokens", "[OPENAI_KEY_1]" in masked and "[AWS_KEY_1]" in masked)
check("secret report counts 4 items", m.report()["secret"] == 4)
check("unmask restores the original", m.unmask(masked) == code)

# --- Personal data ---
personal = {
    "name": "John Smith",
    "email": "john.smith@example.com",
    "phone": "+1 415 555 0132",
    "ssn": "123-45-6789",
    "iban": "GB29NWBK60161331926819",
}
text = (f"My name is {personal['name']}, email {personal['email']}, phone {personal['phone']}, "
        f"SSN {personal['ssn']}, IBAN {personal['iban']}. Write me a confirmation email.")
m2 = Masker()
masked2 = m2.mask(text)
leaks2 = [n for n, s in personal.items() if s in masked2]
check(f"no personal data leaves the device (leaks: {leaks2})", not leaks2)
check("normal words are not masked", "Write me a confirmation email" in masked2)

# --- Encrypted mapping round trip ---
enc = m2.export_encrypted(key)
m3 = Masker()
m3.import_encrypted(key, enc)
check("encrypted mapping decrypts correctly", m3.unmask(masked2) == text)

print(f"\n{passed}/{total} tests passed")
