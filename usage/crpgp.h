#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

struct SecretKeyParamsBuilder *params_builder_new(void);

char params_builder_free(struct SecretKeyParamsBuilder *builder);

char params_builder_primary_user_id(struct SecretKeyParamsBuilder *builder, char *primary_user_id);

struct SecretKeyParams *params_builder_build(struct SecretKeyParamsBuilder *builder);

struct SecretKey *params_generate_secret_key_and_free(struct SecretKeyParams *params);

struct SignedSecretKey *secret_key_sign(struct SecretKey *secret_key);

char secret_key_free(struct SecretKey *secret_key);

struct PublicKey *signed_secret_key_public_key(struct SignedSecretKey *signed_secret_key);

struct Signature *signed_secret_key_create_signature(struct SignedSecretKey *signed_secret_key,
                                              uint8_t *data,
                                              size_t len);

uint8_t *signed_secret_key_decrypt(struct SignedSecretKey *secret_key, uint8_t *encrypted, size_t *len);

char signed_secret_key_free(struct SignedSecretKey *signed_secret_key);

uint8_t *signature_serialize(struct Signature *signature, size_t *output_len);

struct Signature *signature_deserialize(uint8_t *signature_bytes, size_t len);

char signature_free(struct Signature *signature);

char ptr_free(uint8_t *ptr);

char public_key_verify(struct PublicKey *public_key, uint8_t *data, size_t data_len, struct Signature *signature);

char public_key_free(struct PublicKey *public_key);

uint8_t *public_key_encrypt(struct PublicKey *public_key, uint8_t *data, size_t *len);
