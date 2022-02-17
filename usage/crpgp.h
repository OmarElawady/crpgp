#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct SecretKeyParamsBuilder *params_builder_new(void);

void params_builder_free(struct SecretKeyParamsBuilder *builder);

void params_builder_primary_user_id(struct SecretKeyParamsBuilder *builder, char *primary_user_id);

struct SecretKeyParams *params_builder_build(struct SecretKeyParamsBuilder *builder);

struct SecretKey *params_generate_secret_key_and_free(struct SecretKeyParams *params);

struct SignedSecretKey *secret_key_sign_and_free(struct SecretKey *secret_key);

struct PublicKey *signed_secret_key_public_key(struct SignedSecretKey *signed_secret_key);

struct Signature *signed_secret_create_signature(struct SignedSecretKey *signed_secret_key,
                                          uint8_t *data,
                                          size_t len);

uint8_t *signature_serialize(struct Signature *signature, size_t *output_len);

struct Signature *signature_deserialize(uint8_t *signature_bytes, size_t len);

void signature_free(struct Signature *signature);

bool public_key_verify(struct PublicKey *cfg_ptr, uint8_t *data, size_t data_len, struct Signature *signature);

void public_key_free(struct PublicKey *public_key);
