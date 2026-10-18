import seclib
from masker import Masker
from llm_client import call_llm


def run(prompt, shares):
    # 1. reconstruim master key din 3 share-uri (doar local, in memorie)
    key = bytearray(seclib.combine_shares(shares[:3]))
    try:
        m = Masker()
        masked = m.mask(prompt)
        print("\n--- CE VEDE PROVIDERUL (LLM) ---")
        print(masked)

        answer = call_llm(masked)
        print("\n--- RASPUNS BRUT DE LA LLM ---")
        print(answer)

        final = m.unmask(answer)
        print("\n--- RASPUNS FINAL (local, demascat) ---")
        print(final)

        # mapping-ul se pastreaza doar criptat
        blob = m.export_encrypted(bytes(key))
        print("\n--- MAPPING STOCAT (criptat) ---")
        print(blob.hex()[:64], "...")
        return final
    finally:
        # stergem cheia din memorie
        for i in range(len(key)):
            key[i] = 0


if __name__ == "__main__":
    master = seclib.generate_key()
    shares = seclib.split_secret(master, 3, 5)
    del master  # nu mai pastram cheia intreaga, doar share-urile

    prompt = ("Ma numesc Ion Popescu, email ion.popescu@gmail.com, "
              "tel 0712345678, IBAN RO49AAAA1B31007593840000. "
              "Scrie-mi un email de confirmare.")
    run(prompt, shares)
