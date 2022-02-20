#include "crpgp.h"
#include <stdio.h>

int main() {
    char err_buf[1024];
    struct SecretKeyParamsBuilder *builder = params_builder_new();
    if (params_builder_primary_user_id(builder, NULL) != 0) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);
    }
    params_builder_primary_user_id(builder, "Omar Elawady <elawadio@incubaid.com>");    
    struct SecretKeyParams *params = params_builder_build(builder);
    params_builder_free(builder);
    struct SecretKey *sk = params_generate_secret_key_and_free(params);
    struct SignedSecretKey *signed_sk = secret_key_sign(sk);
    struct PublicKey *pk = signed_secret_key_public_key(signed_sk);
    uint8_t *data = (uint8_t*)"omar";
    size_t len = sizeof(data);
    struct Signature *sig = signed_secret_key_create_signature(signed_sk, data, len);
    size_t sig_len;
    uint8_t *serialized = signature_serialize(sig, &sig_len);
    struct Signature *deserialized = signature_deserialize(serialized, sig_len);
    if (public_key_verify(pk, data, len, deserialized) == 0) {
        puts("success");
    } else {
        puts("failure");
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);
    }
    public_key_free(pk);
    signature_free(sig);
    signed_secret_key_free(signed_sk);
    signature_free(deserialized);
    signature_serialization_free(serialized);
}
