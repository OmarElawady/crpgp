use core::ffi::c_void;
use libc::c_char;
use pgp;

#[repr(C)]
pub struct PublicKey {
    pub internal: *mut c_void,
}
#[repr(C)]
pub struct SecretKey {
    pub internal: *mut c_void,
}

#[repr(C)]
pub struct SignedSecretKey {
    pub internal: *mut c_void,
}

#[repr(C)]
pub struct SecretKeyParams {
    pub key_type: KeyType,

    pub can_sign: bool,
    pub can_create_certificates: bool,
    pub can_encrypt: bool,

    // -- Preferences
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    pub preferred_symmetric_algorithms: SymmetricKeyAlgorithm,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    pub preferred_hash_algorithms: HashAlgorithm,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    pub preferred_compression_algorithms: CompressionAlgorithm,
    // TODO: support revocation_key :P
    // revocation_key: Option<RevocationKey>,

    pub primary_user_id: *const c_char,

    // pub user_ids: Vec<String>,
    // pub user_attributes: Vec<UserAttribute>,
    // pub passphrase: Option<*const c_char>,
    pub packet_version: Version,
    pub version: KeyVersion,
    // TODO: support expiration
    // expiration: Option<Duration>,

    // pub subkeys: Vec<SubkeyParams>,
}
// #[repr(C)]
// pub struct SubkeyParams {
//     key_type: KeyType,

//     can_sign: bool,
//     can_create_certificates: bool,
//     can_encrypt: bool,

//     user_ids: Vec<UserId>,
//     user_attributes: Vec<UserAttribute>,
//     passphrase: Option<String>,
//     created_at: chrono::DateTime<chrono::Utc>,
//     packet_version: Version,
//     version: KeyVersion,
//     // TODO: support expiration
//     // expiration: Option<Duration>,
// }

#[repr(C)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}
impl KeyVersion {
    pub fn as_lib(&self) -> pgp::types::KeyVersion {
        match self {
            Self::V2 => pgp::types::KeyVersion::V2,
            Self::V3 => pgp::types::KeyVersion::V3,
            Self::V4 => pgp::types::KeyVersion::V4,
            Self::V5 => pgp::types::KeyVersion::V5,
        }
    }
}
#[repr(C)]
pub enum UserAttribute {
    Image {
        packet_version: Version,
        header: Vec<u8>,
        data: Vec<u8>,
    },
    Unknown {
        packet_version: Version,
        typ: u8,
        data: Vec<u8>,
    },
}
#[repr(C)]
pub struct UserId {
    packet_version: Version,
    id: String,
}
#[repr(C)]
pub enum Version {
    /// Old Packet Format
    Old = 0,
    /// New Packet Format
    New = 1,
}
impl Version {
    pub fn as_lib(&self) -> pgp::types::Version {
        match self {
            Self::Old => pgp::types::Version::Old,
            Self::New => pgp::types::Version::New,
        }
    }
}
#[repr(C)]
pub enum SymmetricKeyAlgorithm {
    /// Plaintext or unencrypted data
    Plaintext = 0,
    /// IDEA
    IDEA = 1,
    /// Triple-DES
    TripleDES = 2,
    /// CAST5
    CAST5 = 3,
    /// Blowfish
    Blowfish = 4,
    // 5 & 6 are reserved for DES/SK
    /// AES with 128-bit key
    AES128 = 7,
    /// AES with 192-bit key
    AES192 = 8,
    /// AES with 256-bit key
    AES256 = 9,
    /// Twofish with 256-bit key
    Twofish = 10,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 128-bit key
    Camellia128 = 11,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 192-bit key
    Camellia192 = 12,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 256-bit key
    Camellia256 = 13,
    Private10 = 110,
}

impl SymmetricKeyAlgorithm {
    pub fn as_lib(&self) -> pgp::crypto::SymmetricKeyAlgorithm {
        match self {
            Self::Plaintext => pgp::crypto::SymmetricKeyAlgorithm::Plaintext,
            Self::IDEA => pgp::crypto::SymmetricKeyAlgorithm::IDEA,
            Self::TripleDES => pgp::crypto::SymmetricKeyAlgorithm::TripleDES,
            Self::CAST5 => pgp::crypto::SymmetricKeyAlgorithm::CAST5,
            Self::Blowfish => pgp::crypto::SymmetricKeyAlgorithm::Blowfish,
            Self::AES128 => pgp::crypto::SymmetricKeyAlgorithm::AES128,
            Self::AES192 => pgp::crypto::SymmetricKeyAlgorithm::AES192,
            Self::AES256 => pgp::crypto::SymmetricKeyAlgorithm::AES256,
            Self::Twofish => pgp::crypto::SymmetricKeyAlgorithm::Twofish,
            Self::Camellia128 => pgp::crypto::SymmetricKeyAlgorithm::Camellia128,
            Self::Camellia192 => pgp::crypto::SymmetricKeyAlgorithm::Camellia192,
            Self::Camellia256 => pgp::crypto::SymmetricKeyAlgorithm::Camellia256,
            Self::Private10 => pgp::crypto::SymmetricKeyAlgorithm::Private10,
        }
    }
}
#[repr(C)]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
    /// Do not use, just for compatability with GnuPG.
    CompressionAlgorithmPrivate10 = 110,
}
impl CompressionAlgorithm {
    pub fn as_lib(&self) -> pgp::types::CompressionAlgorithm {
        match self {
            Self::Uncompressed => pgp::types::CompressionAlgorithm::Uncompressed,
            Self::ZIP => pgp::types::CompressionAlgorithm::ZIP,
            Self::ZLIB => pgp::types::CompressionAlgorithm::ZLIB,
            Self::BZip2 => pgp::types::CompressionAlgorithm::BZip2,
            Self::CompressionAlgorithmPrivate10 => pgp::types::CompressionAlgorithm::Private10,
        }
    }
}

// #[derive(Default)]
#[repr(C)]
pub enum KeyType {
    /// Encryption & Signing with RSA an the given bitsize.
    Rsa(u32),
    /// Encrypting with Curve25519
    ECDH,
    /// Signing with Curve25519
    EdDSA,
}
impl KeyType {
    pub fn as_lib(&self) -> pgp::KeyType {
        match self {
            Self::Rsa(v) => pgp::KeyType::Rsa(*v),
            Self::ECDH => pgp::KeyType::ECDH,
            Self::EdDSA => pgp::KeyType::ECDH,
        }
    }
}
#[repr(C)]
pub struct KeyId([u8; 8]);
#[repr(C)]
pub enum HashAlgorithm {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA2_256 = 8,
    SHA2_384 = 9,
    SHA2_512 = 10,
    SHA2_224 = 11,
    SHA3_256 = 12,
    SHA3_512 = 14,

    /// Do not use, just for compatability with GnuPG.
    HashAlgorithmPrivate10 = 110,
}
impl HashAlgorithm {
    pub fn as_lib(&self) -> pgp::crypto::hash::HashAlgorithm {
        match self {
            Self::None => pgp::crypto::hash::HashAlgorithm::None,
            Self::MD5 => pgp::crypto::hash::HashAlgorithm::MD5,
            Self::SHA1 => pgp::crypto::hash::HashAlgorithm::SHA1,
            Self::RIPEMD160 => pgp::crypto::hash::HashAlgorithm::RIPEMD160,
            Self::SHA2_256 => pgp::crypto::hash::HashAlgorithm::SHA2_256,
            Self::SHA2_384 => pgp::crypto::hash::HashAlgorithm::SHA2_384,
            Self::SHA2_512 => pgp::crypto::hash::HashAlgorithm::SHA2_512,
            Self::SHA2_224 => pgp::crypto::hash::HashAlgorithm::SHA2_224,
            Self::SHA3_256 => pgp::crypto::hash::HashAlgorithm::SHA3_256,
            Self::SHA3_512 => pgp::crypto::hash::HashAlgorithm::SHA3_512,
            Self::HashAlgorithmPrivate10 => pgp::crypto::hash::HashAlgorithm::Private10,
        }
    }
}
#[repr(C)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign)
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only)
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only)
    RSASign = 3,
    /// Elgamal (Sign-Only)
    ElgamalSign = 16,
    /// DSA (Digital Signature Algorithm)
    DSA = 17,
    /// Elliptic Curve: RFC-6637
    ECDH = 18,
    /// ECDSA: RFC-6637
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
    /// EdDSA (not yet assigned)
    EdDSA = 22,
    /// Private experimental range (from OpenGPG)
    // TODO: genenric Unknown(u8)
    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,
}

#[repr(C)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

#[repr(C)]
pub enum SignatureType {
    /// Signature of a binary document.
    /// This means the signer owns it, created it, or certifies that ithas not been modified.
    Binary = 0x00,
    /// Signature of a canonical text document.
    /// This means the signer owns it, created it, or certifies that it
    /// has not been modified.  The signature is calculated over the text
    /// data with its line endings converted to <CR><LF>.
    Text = 0x01,
    /// Standalone signature.
    /// This signature is a signature of only its own subpacket contents.
    /// It is calculated identically to a signature over a zero-length
    /// binary document.  Note that it doesn't make sense to have a V3 standalone signature.
    Standalone = 0x02,
    /// Generic certification of a User ID and Public-Key packet.
    /// The issuer of this certification does not make any particular
    /// assertion as to how well the certifier has checked that the owner
    /// of the key is in fact the person described by the User ID.
    CertGeneric = 0x10,
    /// Persona certification of a User ID and Public-Key packet.
    /// The issuer of this certification has not done any verification of
    /// the claim that the owner of this key is the User ID specified.
    CertPersona = 0x11,
    /// Casual certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done some casual
    /// verification of the claim of identity.
    CertCasual = 0x12,
    /// Positive certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done substantial
    /// verification of the claim of identity.
    ///
    /// Most OpenPGP implementations make their "key signatures" as 0x10
    /// certifications.  Some implementations can issue 0x11-0x13
    /// certifications, but few differentiate between the types.
    CertPositive = 0x13,
    /// Subkey Binding Signature
    /// This signature is a statement by the top-level signing key that
    /// indicates that it owns the subkey.  This signature is calculated
    /// directly on the primary key and subkey, and not on any User ID or
    /// other packets.  A signature that binds a signing subkey MUST have
    /// an Embedded Signature subpacket in this binding signature that
    /// contains a 0x19 signature made by the signing subkey on the
    /// primary key and subkey.
    SubkeyBinding = 0x18,
    /// Primary Key Binding Signature
    /// This signature is a statement by a signing subkey, indicating
    /// that it is owned by the primary key and subkey.  This signature
    /// is calculated the same way as a 0x18 signature: directly on the
    /// primary key and subkey, and not on any User ID or other packets.
    KeyBinding = 0x19,
    /// Signature directly on a key
    /// This signature is calculated directly on a key.  It binds the
    /// information in the Signature subpackets to the key, and is
    /// appropriate to be used for subpackets that provide information
    /// about the key, such as the Revocation Key subpacket.  It is also
    /// appropriate for statements that non-self certifiers want to make
    /// about the key itself, rather than the binding between a key and a name.
    Key = 0x1F,
    /// Key revocation signature
    /// The signature is calculated directly on the key being revoked.  A
    /// revoked key is not to be used.  Only revocation signatures by the
    /// key being revoked, or by an authorized revocation key, should be
    /// considered valid revocation signatures.
    KeyRevocation = 0x20,
    /// Subkey revocation signature
    /// The signature is calculated directly on the subkey being revoked.
    /// A revoked subkey is not to be used.  Only revocation signatures
    /// by the top-level signature key that is bound to this subkey, or
    /// by an authorized revocation key, should be considered valid
    /// revocation signatures.
    SubkeyRevocation = 0x28,
    /// Certification revocation signature
    /// This signature revokes an earlier User ID certification signature
    /// (signature class 0x10 through 0x13) or direct-key signature
    /// (0x1F).  It should be issued by the same key that issued the
    /// revoked signature or an authorized revocation key.  The signature
    /// is computed over the same data as the certificate that it
    /// revokes, and should have a later creation date than that
    /// certificate.
    CertRevocation = 0x30,
    /// Timestamp signature.
    /// This signature is only meaningful for the timestamp contained in
    /// it.
    Timestamp = 0x40,
    /// Third-Party Confirmation signature.
    /// This signature is a signature over some other OpenPGP Signature
    /// packet(s).  It is analogous to a notary seal on the signed data.
    /// A third-party signature SHOULD include Signature Target
    /// subpacket(s) to give easy identification.  Note that we really do
    /// mean SHOULD.  There are plausible uses for this (such as a blind
    /// party that only sees the signature, not the key or source
    /// document) that cannot include a target subpacket.
    ThirdParty = 0x50,
}