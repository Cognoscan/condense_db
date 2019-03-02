//!
//! This contains all the internal structures and unsafe calls to libsodium. None of these should 
//! be used outside of the crypto module.
//!
//! Signing keys are all ed25519, encrypting keys are curve25519, secret keys are 32-byte shared 
//! secrets used for XChaCha20.

use std::ops::Drop;
use std::fmt;
use std::ptr;
use std::ffi::CString;
use libc::c_ulonglong;
use libsodium_sys;
use constant_time_eq::constant_time_eq;

use crypto::error::CryptoError;

const SECRET_KEY_BYTES:   usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
const NONCE_BYTES:        usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
const TAG_BYTES:          usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
const SEED_KEY_BYTES:     usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;
const SK_SIGN_KEY_BYTES:  usize = libsodium_sys::crypto_sign_ed25519_SECRETKEYBYTES as usize;
const SK_CRYPT_KEY_BYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES as usize;
const PK_SIGN_KEY_BYTES:  usize = libsodium_sys::crypto_sign_ed25519_PUBLICKEYBYTES as usize;
const PK_CRYPT_KEY_BYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES as usize;
const SIGN_BYTES:         usize = libsodium_sys::crypto_sign_ed25519_BYTES as usize;

// Secret Structs
#[derive(Clone,Default)]
pub struct Seed(pub [u8; SEED_KEY_BYTES]);
#[derive(Clone)]
pub struct SecretSignKey([u8; SK_SIGN_KEY_BYTES]);
#[derive(Clone,Default)]
pub struct SecretCryptKey([u8; SK_CRYPT_KEY_BYTES]);
#[derive(Clone,Default)]
pub struct SecretKey(pub [u8; SECRET_KEY_BYTES]);

// Public Structs
#[derive(Clone,PartialEq,Eq,Hash,Default)]
pub struct PublicSignKey(pub [u8; PK_SIGN_KEY_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default)]
pub struct PublicCryptKey(pub [u8; PK_CRYPT_KEY_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default,Debug)]
pub struct Nonce(pub [u8; NONCE_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default)]
pub struct Tag(pub [u8; TAG_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default,Debug)]
pub struct StreamId(pub [u8; 32]);
#[derive(Clone)]
pub struct Sign(pub [u8; SIGN_BYTES]);
#[derive(Clone)]
pub struct Blake2BState(pub libsodium_sys::crypto_generichash_blake2b_state);

impl Tag {
    pub fn len() -> usize {
        TAG_BYTES
    }
}

impl Default for Sign {
    fn default() -> Sign {
        Sign([0; SIGN_BYTES])
    }
}
impl fmt::Debug for Sign {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(Sign), &self.0[..])
    }
}
impl PartialEq for Sign {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b)
    }
}

impl fmt::Debug for PublicSignKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(PublicSignKey), &self.0[..])
    }
}

impl fmt::Debug for PublicCryptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(PublicCryptKey), &self.0[..])
    }
}

// Seed
impl Drop for Seed {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}
impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(Seed))
    }
}
impl PartialEq for Seed {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretSignKey
impl Default for SecretSignKey {
    fn default() -> SecretSignKey {
        SecretSignKey([0; SK_SIGN_KEY_BYTES])
    }
}
impl Drop for SecretSignKey {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}
impl fmt::Debug for SecretSignKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretSignKey))
    }
}
impl PartialEq for SecretSignKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretCryptKey
impl Drop for SecretCryptKey {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}
impl fmt::Debug for SecretCryptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretCryptKey))
    }
}
impl PartialEq for SecretCryptKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretKey
impl Drop for SecretKey {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretKey))
    }
}
impl PartialEq for SecretKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// Blake2BState
impl Blake2BState {
    pub fn new() -> Blake2BState {
        let mut state: libsodium_sys::crypto_generichash_blake2b_state;
        // Below will only fail or return -1 if we have more than 64 bytes in input or tell it to use a 
        // non-existant key
        unsafe {
            state = ::std::mem::uninitialized();
            libsodium_sys::crypto_generichash_blake2b_init(&mut state, ::std::ptr::null(), 0, 64);
        }
        Blake2BState { 0: state }
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_update(
                &mut self.0,
                data.as_ptr(),
                data.len() as c_ulonglong
            );
        }
    }

    pub fn get_hash(&self, hash: &mut [u8; 64]) {
        let mut temp_state = self.0.clone();
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_final(
                &mut temp_state,
                hash.as_mut_ptr(),
                64
            );
        }
    }

    pub fn finalize(mut self, hash: &mut [u8; 64]) {
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_final(
                &mut self.0,
                hash.as_mut_ptr(),
                64
            );
        }
    }
}


pub fn aead_keygen(key: &mut SecretKey) {
    unsafe { libsodium_sys::crypto_aead_xchacha20poly1305_ietf_keygen(key.0.as_mut_ptr()) };
}

// Does in-place encryption of message and returns HMAC Tag
pub fn aead_encrypt(message: &mut [u8], ad: &[u8], n: &Nonce, k: &SecretKey) -> Tag {
    // tag will store the message authentication tag
    let mut tag = Tag([0; TAG_BYTES]);
    unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            message.as_mut_ptr(),
            tag.0.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad.as_ptr(),
            ad.len() as c_ulonglong, 
            ptr::null_mut(),
            n.0.as_ptr(),
            k.0.as_ptr()
        );
    }
    tag
}

// Does in-place decryption of crypt and returns true if verification succeeds
pub fn aead_decrypt(crypt: &mut [u8], ad: &[u8], tag: &[u8],n: &Nonce, k: &SecretKey) -> bool {
    if unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            crypt.as_mut_ptr(),
            ptr::null_mut(),
            crypt.as_ptr(),
            crypt.len() as c_ulonglong,
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len() as c_ulonglong,
            n.0.as_ptr(),
            k.0.as_ptr()
        )
    } >= 0 {
        true
    } else {
        false
    }
}

// Shouldn't fail as long as the input parameters are valid
pub fn derive_id(k: &SecretKey, id: &mut StreamId) {
    unsafe {
        let ctx = CString::from_vec_unchecked(b"condense".to_vec());
        libsodium_sys::crypto_kdf_derive_from_key(id.0.as_mut_ptr(), id.0.len(), 1, ctx.as_ptr(), k.0.as_ptr());
    };
}

pub fn blake2b( hash: &mut [u8; 64], data: &[u8] ) {
    // The below will only fail if we set up this function wrong.
    unsafe { 
        libsodium_sys::crypto_generichash_blake2b(
            hash.as_mut_ptr(), 64, 
            data.as_ptr(), data.len() as u64,
            ::std::ptr::null(), 0);
    }
}

pub fn calc_secret(pk: &PublicCryptKey, sk: &SecretCryptKey) -> Result<SecretKey,CryptoError> {
    // This can fail with a bad key, so it must be checked
    let mut k: SecretKey = Default::default();
    if unsafe { 
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_beforenm(
            k.0.as_mut_ptr(), pk.0.as_ptr(), sk.0.as_ptr())
    } >= 0 {
        Ok(k)
    }
    else {
        Err(CryptoError::BadKey)
    }
}

pub fn crypt_keypair(pk: &mut PublicCryptKey, sk: &mut SecretCryptKey) {
    unsafe { libsodium_sys::crypto_box_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) };
}

pub fn sign_keypair(pk: &mut PublicSignKey, sk: &mut SecretSignKey) {
    unsafe { libsodium_sys::crypto_sign_keypair(pk.0.as_mut_ptr(),sk.0.as_mut_ptr()) };
}

pub fn sign_seed_keypair(pk: &mut PublicSignKey, sk: &mut SecretSignKey, seed: &Seed) {
    unsafe { libsodium_sys::crypto_sign_seed_keypair(pk.0.as_mut_ptr(),sk.0.as_mut_ptr(), seed.0.as_ptr()) };
}

pub fn ed25519_sk_to_pk(pk: &mut PublicSignKey, sk: &SecretSignKey) {
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_pk(pk.0.as_mut_ptr(),sk.0.as_ptr()) };
}

pub fn ed25519_sk_to_seed(seed: &mut Seed, ed: &SecretSignKey) {
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_seed(seed.0.as_mut_ptr(),ed.0.as_ptr()) };
}

pub fn ed25519_sk_to_curve25519(curve: &mut SecretCryptKey, ed: &SecretSignKey) {
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(curve.0.as_mut_ptr(),ed.0.as_ptr()) };
}

pub fn ed25519_pk_to_curve25519_pk(
    curve: &mut PublicCryptKey,
    ed: &PublicSignKey,
) -> Result<(), CryptoError>
{
    // Can actually fail with a bad key, so check it
    if unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(curve.0.as_mut_ptr(),ed.0.as_ptr())
    } >= 0 {
        Ok(())
    }
    else {
        Err(CryptoError::BadKey)
    }
}

pub fn sign_detached(k: &SecretSignKey, m: &[u8]) -> Sign {
    let mut sig: Sign = Default::default();
    unsafe { libsodium_sys::crypto_sign_ed25519_detached(
            sig.0.as_mut_ptr(),
            ptr::null_mut(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            k.0.as_ptr());
    };
    sig
}

pub fn verify_detached(k: &PublicSignKey, m: &[u8], sig: &Sign) -> bool {
    if unsafe {
        libsodium_sys::crypto_sign_ed25519_verify_detached(
            sig.0.as_ptr(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            k.0.as_ptr())
    } >= 0 {
        true
    } else {
        false
    }
}


pub fn memzero(x: &mut [u8]) {
    unsafe { libsodium_sys::sodium_memzero(x.as_mut_ptr() as *mut _, x.len()); }
}

pub fn randombytes(x: &mut [u8]) {
    unsafe { libsodium_sys::randombytes_buf(x.as_mut_ptr() as *mut _, x.len()); }
}

/// Initializes the underlying crypto library and makes all random number generation functions 
/// thread-safe.
pub fn init() -> Result<(), ()> {
    if unsafe { libsodium_sys::sodium_init() } >= 0 {
        Ok(())
    } else {
        Err(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    const BEFORE_NM_BYTES: usize = libsodium_sys::crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize;

    #[test]
    fn correct_sizes() {
        assert_eq!(BEFORE_NM_BYTES, SECRET_KEY_BYTES);
    }
}
