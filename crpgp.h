#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef SecretKeyParamsBuilder SecretKeyParamsBuilder;

typedef SecretKeyParams SecretKeyParams;

typedef SecretKey SecretKey;

typedef SignedSecretKey SignedSecretKey;

typedef PublicKey PublicKey;

typedef Signature Signature;

SecretKeyParamsBuilder *params_builder_new(void);

void params_builder_free(SecretKeyParamsBuilder *b);

void params_builder_primary_user_id(SecretKeyParamsBuilder *cfg_ptr, char *primary_user_id);

SecretKeyParams *params_builder_build(SecretKeyParamsBuilder *cfg_ptr);

SecretKey *params_generate_secret_key_and_free(SecretKeyParams *cfg_ptr);

SignedSecretKey *secret_key_sign_and_free(SecretKey *cfg_ptr);

PublicKey *signed_secret_key_public_key(SignedSecretKey *cfg_ptr);

Signature *signed_secret_create_signature(SignedSecretKey *cfg_ptr, uint8_t *data, size_t *len);

uint8_t *signature_serialize(Signature *signature, size_t *output_len);

Signature *signature_deserialize(uint8_t *signature_bytes, size_t len);

void signature_free(Signature *signature);

bool public_key_verify(PublicKey *cfg_ptr,
                       uint8_t *data,
                       size_t data_len,
                       uint8_t *signature,
                       size_t signature_len);

void public_key_free(PublicKey *public_key);
