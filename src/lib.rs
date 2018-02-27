
enum TriState {
    Yes,
    No,
    Unknown,
}

/// The encapsulation format for a Table
enum TableFormat {
    /// No cryptography
    Plain,
    /// Table header is encrypted
    Encrypted,
    /// Table header is signed
    Signed,
    /// Table header is signed, encryption was applied after
    SignedThenEncrypted,
    /// Table header is encrypted, then encrypted result was signed
    EncryptedThenSigned,
}

enum EntryFormat {
    /// Only the 64-bit ID prefixes the entry
    Id,
    /// Contents encrypted & prefixed with ID
    EncryptedThenId,
    /// ID & contents encrypted 
    IdThenEncrypted,
    /// ID & contents signed
    IdSigned,
    /// ID & contents signed then encrypted
    IdSignedThenEncrypted,
    /// contents signed & encrypted, then prefixed with ID
    SignedThenEncryptedThenId,
    /// contents encrypted, prefixed with ID, and signed
    EncryptedThenIdSigned,
};


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

enum EntryType {
    /// File: fixed # of entries, ordered unique entry IDs
    File,
    /// List: variable # of entries, multiple entries per ID allowed
    List
    /// UniqueList: variable # of entries, only one entry per ID
    UniqueList,
    /// ParsedList: parsable variable # of entries, multiple entries per ID allowed
    ParsedList,
    /// ParsedUniqueList: parsable variable # of entries, only one entry per ID
    ParsedUniqueList,
}
    
enum HashOrder {
    List,
    BinaryTree,
}


/// Table
/// =====
/// A Table consists of a descriptive header and a series of entries. A header describes the type 
/// and format of the entries, the content hashes (for files), and has optional fields for a name,
/// tags, and application-specific data. A header can always be located by its cryptographic hash. 
///
/// In addition to the contents, the table header can be signed and encrypted in any order. A 
/// header is never stored if the contents cannot be decrypted. Individual entries may be 
/// unreadable by the local database, but the table header must always be readable.
///
/// All table entries are numbered by a 64-bit ID. The entries may be in one of the following 
/// formats:
/// - File: Unique IDs starting from 0, Fixed in content and quantity
/// - List: Non-Unique IDs, variable quantity
/// - UniqueList: Unique IDs, variable quantity
/// - ParsedList: Non-Unique IDs, variable quantity, entries can be parsed into simple data structures
/// - ParsedUniqueList: Unique IDs, variable quantity, eentries can be parsed into simple data structures
///
/// Entries can be found using their ID or the hash of the entry. For ParsedList and 
/// ParsedUniqueList, they can also be located by selecting them based on the contents of their 
/// data structures.
struct Table {
    /// Raw contents of the db_header, before parsing
    raw: Vec<u8>,
    // Metadata
    /// Scope of access
    is_public: bool,
    is_friends: bool,
    is_nearby: bool,
    stored_by: MultiKey,
    is_pinned: bool,
    /// Hashes of header
    meta_hash: Vec<MultiHash>,
    /// Format in which header is encoded
    meta_format: TableFormat,
    /// Encryption status
    meta_is_encrypted: bool,
    meta_can_decrypt: bool,
    meta_encryption_type: MultiEncrypt,
    meta_encryption_key: MultiKey,
    /// Signature status
    meta_is_signed: bool,
    meta_signature: MultiSignature,
    // Contents
    /// Name for this Table. Does not have to be unique. Empty string is different from no string!
    name: Option<String>,
    /// UTF-8 tags describing this Table. Can be used when searching.
    tags: Vec<String>,
    /// Data related to proper usage of this Table
    app_data: Vec<u8>,
    /// Maximum entry size, in bytes
    max_entry_size: u64,
    /// Describes the type of data this Table will reference
    entry_type: Option<EntryType>,
    /// Format in which entries shall be encoded
    entry_format: Option<EntryFormat>,
    /// Key to unlock entries, if required
    entry_key: Option<MultiKey>,
    /// Ordering format of content hashes in entry_hashes. Used only by File EntryType.
    hash_ordering: Option<HashOrder>,
    /// Optional content hashes. Ordering determiend by hash_ordering. Used only by File EntryType.
    entry_hashes: Vec<MultiHash>,
}

/// Entry
/// =====
/// An entry in a table. Contains data, optionally encrypted and/or signed. Always has an 
/// associated ID that may or may not be unique.
struct Entry {
    // Data
    id: u64,
    /// Raw data in entry
    raw: Vec<u8>,
    /// Pointer to where entry content begins
    data_ptr: usize,
    // Metadata
    /// Scope of access
    is_public: bool,
    is_friends: bool,
    is_nearby: bool,
    stored_by: MultiKey,
    is_pinned: bool,
    /// Hashes of entry
    meta_hash: Vec<MultiHash>,
    /// Encryption status
    meta_is_encrypted: bool,
    meta_can_decrypt: bool,
    meta_encryption_type: MultiEncrypt,
    meta_encryption_key: MultiKey,
    /// Signature status
    meta_is_signed: bool,
    meta_signature: MultiSignature,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
