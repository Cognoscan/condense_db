/// A format encoding a cryptographic hash
struct MultiHash {
    code: u32,
    size: u32,
    hash: Vec<u8>
}

/// A format encoding a cryptographic key
struct MultiKey {
    code: u32,
    size: u32,
    key_type: u32,
    crypto_type: u32,
    crypto_scheme: u32,
    key: Vec<u8>
}

/// A format encoding the prelude for an encrypted block
struct MultiEncrypt {
    code: u32,
    size: u32,
    side_channel: Vec<u8>,
}

/// A format encoding a cryptographic signature
struct MultiSignature {
    code: u32,
    size: u32,
    side_channel: Vec<u8>,
}
impl MultiSignature {
    /// Determine if the signature is valid for a given key
    pub fn is_signed_by(key: MultiKey) -> bool {
        false
    }
}
