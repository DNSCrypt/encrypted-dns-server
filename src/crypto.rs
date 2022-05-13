use std::ffi::CStr;
use std::hash::Hasher;
use std::ptr;

use libsodium_sys::*;
use serde_big_array::BigArray;
use siphasher::sip::SipHasher13;

use crate::errors::*;

#[derive(Derivative)]
#[derivative(Default)]
pub struct Signature(
    #[derivative(Default(value = "[0u8; crypto_sign_BYTES as usize]"))]
    [u8; crypto_sign_BYTES as usize],
);

impl Signature {
    pub fn as_bytes(&self) -> &[u8; crypto_sign_BYTES as usize] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; crypto_sign_BYTES as usize]) -> Self {
        Signature(bytes)
    }
}

#[derive(Serialize, Deserialize, Derivative, Clone)]
#[derivative(Default)]
pub struct SignSK(
    #[serde(with = "BigArray")]
    #[derivative(Default(value = "[0u8; crypto_sign_SECRETKEYBYTES as usize]"))]
    [u8; crypto_sign_SECRETKEYBYTES as usize],
);

impl SignSK {
    pub fn as_bytes(&self) -> &[u8; crypto_sign_SECRETKEYBYTES as usize] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; crypto_sign_SECRETKEYBYTES as usize]) -> Self {
        SignSK(bytes)
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        let mut signature = Signature::default();
        let ret = unsafe {
            crypto_sign_detached(
                signature.0.as_mut_ptr(),
                ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as _,
                self.as_bytes().as_ptr(),
            )
        };
        assert_eq!(ret, 0);
        signature
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SignPK([u8; crypto_sign_PUBLICKEYBYTES as usize]);

impl SignPK {
    pub fn as_bytes(&self) -> &[u8; crypto_sign_PUBLICKEYBYTES as usize] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; crypto_sign_PUBLICKEYBYTES as usize]) -> Self {
        SignPK(bytes)
    }

    pub fn as_string(&self) -> String {
        bin2hex(self.as_bytes())
    }
}

#[derive(Derivative, Serialize, Deserialize, Clone)]
#[derivative(Debug, Default)]
pub struct SignKeyPair {
    #[derivative(Debug = "ignore")]
    pub sk: SignSK,
    pub pk: SignPK,
}

impl SignKeyPair {
    pub fn new() -> Self {
        let mut kp = SignKeyPair::default();
        unsafe { crypto_sign_keypair(kp.pk.0.as_mut_ptr(), kp.sk.0.as_mut_ptr()) };
        kp
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CryptSK([u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize]);

impl CryptSK {
    pub fn as_bytes(
        &self,
    ) -> &[u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize] {
        &self.0
    }

    pub fn from_bytes(
        bytes: [u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize],
    ) -> Self {
        CryptSK(bytes)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CryptPK([u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize]);

impl CryptPK {
    pub fn as_bytes(
        &self,
    ) -> &[u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize] {
        &self.0
    }

    pub fn from_bytes(
        bytes: [u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize],
    ) -> Self {
        CryptPK(bytes)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CryptKeyPair {
    pub sk: CryptSK,
    pub pk: CryptPK,
}

impl CryptKeyPair {
    pub fn from_seed(
        seed: [u8; crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize],
    ) -> Self {
        let mut kp = CryptKeyPair::default();
        unsafe {
            crypto_box_curve25519xchacha20poly1305_seed_keypair(
                kp.pk.0.as_mut_ptr(),
                kp.sk.0.as_mut_ptr(),
                seed.as_ptr(),
            )
        };
        kp
    }

    pub fn compute_shared_key(&self, pk: &[u8]) -> Result<SharedKey, Error> {
        let mut shared_key = SharedKey::default();
        let res = unsafe {
            crypto_box_curve25519xchacha20poly1305_beforenm(
                shared_key.0.as_mut_ptr(),
                pk.as_ptr(),
                self.sk.0.as_ptr(),
            )
        };
        ensure!(res == 0, "Weak public key");
        Ok(shared_key)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SharedKey([u8; crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize]);

impl SharedKey {
    pub fn decrypt(&self, nonce: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, Error> {
        let encrypted_len = encrypted.len();
        let mut decrypted =
            vec![0u8; encrypted_len - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let res = unsafe {
            libsodium_sys::crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
                decrypted.as_mut_ptr(),
                encrypted.as_ptr(),
                encrypted_len as _,
                nonce.as_ptr(),
                self.0.as_ptr(),
            )
        };
        ensure!(res == 0, "Unable to decrypt");
        let idx = decrypted
            .iter()
            .rposition(|x| *x != 0x00)
            .ok_or_else(|| anyhow!("Padding error"))?;
        ensure!(decrypted[idx] == 0x80, "Padding error");
        decrypted.truncate(idx);
        Ok(decrypted)
    }

    pub fn encrypt_into(
        &self,
        target: &mut Vec<u8>,
        nonce: &[u8],
        client_nonce: &[u8],
        plaintext: Vec<u8>,
        max_target_size: usize,
    ) -> Result<(), Error> {
        ensure!(
            max_target_size >= crypto_box_curve25519xchacha20poly1305_MACBYTES as usize,
            "Max target size too small"
        );
        let plaintext_len = plaintext.len();
        let max_padded_plaintext_len =
            max_target_size - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;
        let mut hasher = SipHasher13::new();
        hasher.write(&self.0);
        hasher.write(client_nonce);
        let pad_size: usize = 1 + (hasher.finish() as usize & 0xff);
        let mut padded_plaintext_len = (plaintext_len + pad_size) & !63;
        if padded_plaintext_len < plaintext_len {
            padded_plaintext_len += 256;
        }
        if padded_plaintext_len > max_padded_plaintext_len {
            padded_plaintext_len = max_padded_plaintext_len;
        }
        ensure!(padded_plaintext_len > plaintext_len, "No room for padding");
        let mut padded_plaintext = plaintext;
        padded_plaintext.push(0x80);
        while padded_plaintext.len() != padded_plaintext_len {
            padded_plaintext.push(0x00);
        }
        let padded_plaintext_len = padded_plaintext.len();
        let target_header_len = target.len();
        target.resize(
            target_header_len
                + padded_plaintext_len
                + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize,
            0,
        );
        let encrypted = &mut target[target_header_len..];
        let res = unsafe {
            libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy_afternm(
                encrypted.as_mut_ptr(),
                padded_plaintext.as_ptr(),
                padded_plaintext_len as _,
                nonce.as_ptr(),
                self.0.as_ptr(),
            )
        };
        ensure!(res == 0, "Unable to encrypt");
        Ok(())
    }
}

pub fn bin2hex(bin: &[u8]) -> String {
    let bin_len = bin.len();
    let hex_len = bin_len * 2 + 1;
    let mut hex = vec![0u8; hex_len];
    unsafe {
        sodium_bin2hex(hex.as_mut_ptr() as *mut _, hex_len, bin.as_ptr(), bin_len);
    }
    CStr::from_bytes_with_nul(&hex)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

pub fn init() -> Result<(), Error> {
    let res = unsafe { sodium_init() };
    ensure!(res >= 0, "Unable to initialize libsodium");
    Ok(())
}
