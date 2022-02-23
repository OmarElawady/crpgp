#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

int last_error_length(void);

/**
 * Write the latest error message to a buffer.
 *
 * # Returns
 *
 * This returns the number of bytes written to the buffer. If no bytes were
 * written (i.e. there is no last error) then it returns `0`. If the buffer
 * isn't big enough or a `null` pointer was passed in, you'll get a `-1`.
 */
int error_message(char *buffer, int length);

char public_key_verify(PublicKey *public_key, uint8_t *data, size_t data_len, Signature *signature);

uint8_t *public_key_encrypt(PublicKey *public_key, uint8_t *data, size_t *len);

SignedPublicKey *public_key_sign_and_free(PublicKey *public_key, SignedSecretKey *secret_key);

char public_key_free(PublicKey *public_key);

SignedSecretKey *secret_key_sign(SecretKey *secret_key);

char secret_key_free(SecretKey *secret_key);

SecretKey *params_generate_secret_key_and_free(SecretKeyParams *params);

SecretKeyParamsBuilder *params_builder_new(void);

char params_builder_primary_user_id(SecretKeyParamsBuilder *builder, char *primary_user_id);

char params_builder_key_type(SecretKeyParamsBuilder *builder, struct KeyType key_type);

char params_builder_subkey(SecretKeyParamsBuilder *builder, SubkeyParams *subkey);

SecretKeyParams *params_builder_build(SecretKeyParamsBuilder *builder);

char params_builder_free(SecretKeyParamsBuilder *builder);

uint8_t *signature_serialize(Signature *signature, size_t *output_len);

Signature *signature_deserialize(uint8_t *signature_bytes, size_t len);

char signature_free(Signature *signature);

char signed_public_key_verify(SignedPublicKey *signed_public_key,
                              uint8_t *data,
                              size_t data_len,
                              Signature *signature);

uint8_t *signed_public_key_encrypt(SignedPublicKey *signed_public_key, uint8_t *data, size_t *len);

uint8_t *signed_public_key_encrypt_with_any(SignedPublicKey *signed_public_key,
                                            uint8_t *data,
                                            size_t *len);

uint8_t *signed_public_key_to_bytes(SignedPublicKey *signed_public_key, size_t *len);

SignedPublicKey *signed_public_key_from_bytes(uint8_t *bytes, size_t len);

char *signed_public_key_to_armored(SignedPublicKey *signed_public_key);

SignedPublicKey *signed_public_key_from_armored(char *s);

char signed_public_key_free(SignedPublicKey *public_key);

PublicKey *signed_secret_key_public_key(SignedSecretKey *signed_secret_key);

Signature *signed_secret_key_create_signature(SignedSecretKey *signed_secret_key,
                                              uint8_t *data,
                                              size_t len);

uint8_t *signed_secret_key_decrypt(SignedSecretKey *secret_key, uint8_t *encrypted, size_t *len);

char signed_secret_key_free(SignedSecretKey *signed_secret_key);

uint8_t *signed_secret_key_to_bytes(SignedSecretKey *signed_secret_key, size_t *len);

SignedSecretKey *signed_secret_key_from_bytes(uint8_t *bytes, size_t len);

char *signed_secret_key_to_armored(SignedSecretKey *signed_secret_key);

SignedSecretKey *signed_secret_key_from_armored(char *s);

char subkey_params_free(SubkeyParams *subkey_params);

SubkeyParamsBuilder *subkey_params_builder_new(void);

char subkey_params_builder_key_type(SubkeyParamsBuilder *builder, struct KeyType key_type);

char subkey_params_builder_free(SubkeyParamsBuilder *builder);

SubkeyParams *subkey_params_builder_build(SubkeyParamsBuilder *builder);

char ptr_free(uint8_t *ptr);
