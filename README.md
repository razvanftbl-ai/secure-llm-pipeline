# Secure LLM Pipeline

Pipeline local care trimite prompturi către un LLM **fără ca providerul să vadă date sensibile** și fără ca vreodată să primească o cheie de criptare.

Track: AI pipeline secret sharing.

## Arhitectură

1. **Master key** (256 biți) generată local cu `OsRng`, apoi împărțită cu **Shamir 3-din-5** peste GF(256). Cheia întreagă nu este stocată.
2. **Mascare**: datele sensibile (email, telefon, IBAN, CNP, card, nume) sunt înlocuite cu token-uri `[EMAIL_1]`, `[PERSON_1]` etc.
3. **LLM-ul primește doar textul mascat.** Nu primește nicio cheie.
4. **Mapping-ul** token → valoare reală este criptat cu **AES-256-GCM** (nonce aleator, AAD) și rămâne local.
5. **Răspunsul** este demascat local.
6. Cheia se reconstruiește în memorie doar cât e necesar, apoi se zeroizează.

## Nucleul criptografic (Rust)

- `seclib` (Rust + PyO3): AES-256-GCM, Shamir Secret Sharing implementat peste GF(256) cu aritmetică **fără ramificări dependente de secret**.
- Interpolare Lagrange în x = 0, polinoame aleatoare de grad t-1.
- Zeroizare cu crate-ul `zeroize`.

## Model de amenințare

Adversar: providerul LLM (curios sau compromis) și un observator de rețea. Se presupune că dispozitivul local nu este compromis.

## Vulnerabilități acoperite

| Risc | Mitigare |
|---|---|
| Date sensibile ajung la provider | Mascare înainte de trimitere |
| Master key în prompt/loguri | Cheia nu pleacă niciodată de pe dispozitiv |
| Compromiterea unui singur loc de stocare | Shamir 3-din-5 |
| Reutilizare nonce AES-GCM | Nonce aleator de 96 biți pe fiecare criptare |
| Modificarea datelor | Tag de autentificare GCM |
| Ciphertext folosit în alt context | AAD |
| Cheie rămasă în memorie | Zeroizare în Rust și ștergere în Python |
| Istoric păstrat de provider | `store: false` în apelul API |

## Limitări (onest)

- Detectarea cu regex nu prinde orice (nume cu litere mici, formate neobișnuite). Producția ar necesita NER local.
- Contextul rămâne vizibil providerului (ex: „fiica mea de 7 ani din Iași").
- Obiectele `bytes` din Python sunt imutabile și nu pot fi zeroizate complet.
- Lungimea mesajului nu este ascunsă.
- Un atacator cu acces la dispozitiv în timpul rulării poate citi memoria.

## Rulare

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install maturin requests textual
maturin develop
python test_security.py
python tui.py
```

Opțional: `export OPENAI_API_KEY=...` pentru LLM real. Fără cheie rulează un mock.
