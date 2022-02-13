#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum CompressionAlgorithm {
  Uncompressed = 0,
  ZIP = 1,
  ZLIB = 2,
  BZip2 = 3,
  /**
   * Do not use, just for compatability with GnuPG.
   */
  CompressionAlgorithmPrivate10 = 110,
} CompressionAlgorithm;

typedef enum HashAlgorithm {
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
  /**
   * Do not use, just for compatability with GnuPG.
   */
  HashAlgorithmPrivate10 = 110,
} HashAlgorithm;

typedef enum KeyVersion {
  V2 = 2,
  V3 = 3,
  V4 = 4,
  V5 = 5,
} KeyVersion;

typedef enum SymmetricKeyAlgorithm {
  /**
   * Plaintext or unencrypted data
   */
  Plaintext = 0,
  /**
   * IDEA
   */
  IDEA = 1,
  /**
   * Triple-DES
   */
  TripleDES = 2,
  /**
   * CAST5
   */
  CAST5 = 3,
  /**
   * Blowfish
   */
  Blowfish = 4,
  /**
   * AES with 128-bit key
   */
  AES128 = 7,
  /**
   * AES with 192-bit key
   */
  AES192 = 8,
  /**
   * AES with 256-bit key
   */
  AES256 = 9,
  /**
   * Twofish with 256-bit key
   */
  Twofish = 10,
  /**
   * [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 128-bit key
   */
  Camellia128 = 11,
  /**
   * [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 192-bit key
   */
  Camellia192 = 12,
  /**
   * [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 256-bit key
   */
  Camellia256 = 13,
  Private10 = 110,
} SymmetricKeyAlgorithm;

typedef enum Version {
  /**
   * Old Packet Format
   */
  Old = 0,
  /**
   * New Packet Format
   */
  New = 1,
} Version;

typedef enum KeyType_Tag {
  /**
   * Encryption & Signing with RSA an the given bitsize.
   */
  Rsa,
  /**
   * Encrypting with Curve25519
   */
  ECDH,
  /**
   * Signing with Curve25519
   */
  EdDSA,
} KeyType_Tag;

typedef struct KeyType {
  KeyType_Tag tag;
  union {
    struct {
      uint32_t rsa;
    };
  };
} KeyType;

typedef struct SecretKeyParams {
  struct KeyType key_type;
  bool can_sign;
  bool can_create_certificates;
  bool can_encrypt;
  /**
   * List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
   */
  enum SymmetricKeyAlgorithm preferred_symmetric_algorithms;
  /**
   * List of hash algorithms that indicate which algorithms the key holder prefers to use.
   */
  enum HashAlgorithm preferred_hash_algorithms;
  /**
   * List of compression algorithms that indicate which algorithms the key holder prefers to use.
   */
  enum CompressionAlgorithm preferred_compression_algorithms;
  const char *primary_user_id;
  enum Version packet_version;
  enum KeyVersion version;
} SecretKeyParams;

typedef struct SecretKey {
  void *internal;
} SecretKey;

typedef struct SignedSecretKey {
  void *internal;
} SignedSecretKey;

typedef struct PublicKey {
  void *internal;
} PublicKey;

struct SecretKeyParams *signature_config_builder_new(void);

void param_set_version(struct SecretKeyParams *cfg_ptr, enum KeyVersion version);

void param_set_primary_user_id(struct SecretKeyParams *cfg_ptr, const char *primary_user_id);

struct SecretKey *generate_secret_key(struct SecretKeyParams *cfg_ptr);

struct SignedSecretKey *sign(struct SecretKey *cfg_ptr);

struct PublicKey *public_key(struct SignedSecretKey *cfg_ptr);
