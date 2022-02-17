#include "crpgp.h"
#include <stdio.h>

int main() {
    struct SecretKeyParamsBuilder *builder = params_builder_new();
    params_builder_primary_user_id(builder, "Omar Elawady <elawadio@incubaid.com>");    
    struct SecretKeyParams *params = params_builder_build(builder);
    params_builder_free(builder);
    struct SecretKey *sk = params_generate_secret_key_and_free(params);
    struct SignedSecretKey *signed_sk = secret_key_sign_and_free(sk);
    struct PublicKey *pk = signed_secret_key_public_key(signed_sk);
    uint8_t *data = (uint8_t*)"omar";
    size_t len = sizeof(data);
    struct Signature *sig = signed_secret_create_signature(signed_sk, data, len);
    size_t sig_len;
    uint8_t *serialized = signature_serialize(sig, &sig_len);
    struct Signature *deserialized = signature_deserialize(serialized, sig_len);
    bool ok = public_key_verify(pk, data, len, deserialized);
    if (ok) {
        puts("success");
    }
    public_key_free(pk);
    signature_free(sig);
    signature_free(deserialized);
}
