import seclib
from masker import Masker

key = seclib.generate_key()
m = Masker()

original = "Ma numesc Ion Popescu, email ion.popescu@gmail.com, tel 0712345678, IBAN RO49AAAA1B31007593840000. Ajuta-ma cu un email."
masked = m.mask(original)
print("TRIMIS LA LLM:", masked)

# simulam un raspuns de la LLM
raspuns = "Buna [PERSON_1], am trimis confirmarea la [EMAIL_1]."
print("RASPUNS DE LA LLM:", raspuns)
print("RASPUNS FINAL:", m.unmask(raspuns))

# mapping criptat
blob = m.export_encrypted(key)
print("MAPPING CRIPTAT:", blob.hex()[:60], "...")
m2 = Masker()
m2.import_encrypted(key, blob)
assert m2.unmask(raspuns) == m.unmask(raspuns)
print("OK: mapping decriptat corect")
