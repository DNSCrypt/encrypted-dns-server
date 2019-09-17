use crate::errors::*;

use libsodium_sys::*;
use std::ffi::CStr;
use std::ptr;

#[allow(non_upper_case_globals)]
pub const crypto_box_curve25519xchacha20poly1305_HALFNONCEBYTES: usize =
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize / 2;

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

#[derive(Derivative)]
#[derivative(Default)]
pub struct SignSK(
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

#[derive(Debug, Default)]
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

#[derive(Derivative)]
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

#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
pub struct CryptKeyPair {
    pub sk: CryptSK,
    pub pk: CryptPK,
}

impl CryptKeyPair {
    pub fn new() -> Self {
        let mut kp = CryptKeyPair::default();
        unsafe {
            crypto_box_curve25519xchacha20poly1305_keypair(
                kp.pk.0.as_mut_ptr(),
                kp.sk.0.as_mut_ptr(),
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

#[derive(Debug, Default)]
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
            .ok_or_else(|| format_err!("Padding error"))?;
        ensure!(decrypted[idx] == 0x80, "Padding error");
        decrypted.truncate(idx);
        Ok(decrypted)
    }

    pub fn encrypt(&self, nonce: &[u8], mut plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
        plaintext.push(0x80);
        let plaintext_len = plaintext.len();
        let mut encrypted =
            vec![0u8; plaintext_len + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let res = unsafe {
            libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy_afternm(
                encrypted.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext_len as _,
                nonce.as_ptr(),
                self.0.as_ptr(),
            )
        };
        ensure!(res == 0, "Unable to encrypt");
        Ok(encrypted)
    }
}

pub fn bin2hex(bin: &[u8]) -> String {
    let bin_len = bin.len();
    let hex_len = bin_len * 2 + 1;
    let mut hex = vec![0u8; hex_len];
    unsafe {
        sodium_bin2hex(hex.as_mut_ptr() as *mut i8, hex_len, bin.as_ptr(), bin_len);
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
