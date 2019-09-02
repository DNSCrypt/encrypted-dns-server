use crate::errors::*;

use libsodium_sys::*;
use std::ffi::CStr;
use std::ptr;

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
