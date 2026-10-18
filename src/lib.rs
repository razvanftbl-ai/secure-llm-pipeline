use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

// ---------- GF(256), polinom AES: x^8 + x^4 + x^3 + x + 1 (0x11B) ----------
// Înmulțire constant-time: fără if / ramificări dependente de date.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        p ^= a & mask;
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    p
}

// Invers multiplicativ: a^254 (mica teoremă a lui Fermat în GF(256)).
// Exponentul e public și fix, deci nu scurge nimic despre `a`.
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

// ---------- AES-256-GCM ----------
#[pyfunction]
fn generate_key<'py>(py: Python<'py>) -> Bound<'py, PyBytes> {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    let out = PyBytes::new_bound(py, &k);
    k.zeroize();
    out
}

/// Returnează nonce(12) || ciphertext || tag(16)
#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None))]
fn encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("invalid key"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: aad.unwrap_or(&[]) },
        )
        .map_err(|_| PyValueError::new_err("encryption failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
#[pyo3(signature = (key, blob, aad=None))]
fn decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    blob: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if blob.len() < 12 + 16 {
        return Err(PyValueError::new_err("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("invalid key"))?;
    let (nonce, ct) = blob.split_at(12);
    let mut pt = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload { msg: ct, aad: aad.unwrap_or(&[]) },
        )
        .map_err(|_| PyValueError::new_err("decryption failed (wrong key or tampered data)"))?;
    let out = PyBytes::new_bound(py, &pt);
    pt.zeroize();
    Ok(out)
}

// ---------- Shamir Secret Sharing peste GF(256) ----------
/// Fiecare share = [x] || [y_0, y_1, ..., y_{L-1}]
#[pyfunction]
fn split_secret<'py>(
    py: Python<'py>,
    secret: &[u8],
    threshold: u8,
    shares: u8,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    if secret.is_empty() {
        return Err(PyValueError::new_err("secret is empty"));
    }
    if threshold < 2 || shares < threshold {
        return Err(PyValueError::new_err("need 2 <= threshold <= shares <= 255"));
    }
    let t = threshold as usize;
    let n = shares as usize;
    let mut out_shares: Vec<Vec<u8>> = (1..=n).map(|x| {
        let mut v = Vec::with_capacity(1 + secret.len());
        v.push(x as u8);
        v
    }).collect();

    for &s in secret {
        // polinom: coef[0] = s, restul aleatoare
        let mut coef = vec![0u8; t];
        coef[0] = s;
        OsRng.fill_bytes(&mut coef[1..]);
        for (i, share) in out_shares.iter_mut().enumerate() {
            let x = (i + 1) as u8;
            // Horner
            let mut y = 0u8;
            for c in coef.iter().rev() {
                y = gf_mul(y, x) ^ c;
            }
            share.push(y);
        }
        coef.zeroize();
    }
    let result = out_shares.iter().map(|s| PyBytes::new_bound(py, s)).collect();
    for s in out_shares.iter_mut() {
        s.zeroize();
    }
    Ok(result)
}

#[pyfunction]
fn combine_shares<'py>(py: Python<'py>, shares: Vec<Vec<u8>>) -> PyResult<Bound<'py, PyBytes>> {
    if shares.len() < 2 {
        return Err(PyValueError::new_err("need at least 2 shares"));
    }
    let len = shares[0].len();
    if len < 2 || shares.iter().any(|s| s.len() != len) {
        return Err(PyValueError::new_err("shares have inconsistent length"));
    }
    let xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    for (i, &x) in xs.iter().enumerate() {
        if x == 0 {
            return Err(PyValueError::new_err("invalid share index"));
        }
        if xs[..i].contains(&x) {
            return Err(PyValueError::new_err("duplicate share index"));
        }
    }
    // Coeficienții Lagrange în x = 0: l_i = prod_{j!=i} x_j / (x_i ^ x_j)
    let mut lag = vec![0u8; xs.len()];
    for i in 0..xs.len() {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..xs.len() {
            if i != j {
                num = gf_mul(num, xs[j]);
                den = gf_mul(den, xs[i] ^ xs[j]);
            }
        }
        lag[i] = gf_mul(num, gf_inv(den));
    }
    let mut secret = vec![0u8; len - 1];
    for k in 0..secret.len() {
        let mut acc = 0u8;
        for (i, s) in shares.iter().enumerate() {
            acc ^= gf_mul(s[k + 1], lag[i]);
        }
        secret[k] = acc;
    }
    let out = PyBytes::new_bound(py, &secret);
    secret.zeroize();
    Ok(out)
}

#[pymodule]
fn seclib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(split_secret, m)?)?;
    m.add_function(wrap_pyfunction!(combine_shares, m)?)?;
    Ok(())
}