#[allow(dead_code)]
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
            Self::EdDSA => pgp::KeyType::EdDSA,
        }
    }
}