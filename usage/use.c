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
    len = sizeof(data);
    uint8_t *encrypted = public_key_encrypt(pk, data, &len);
    if (encrypted == NULL) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);    
        return -1;
    }
    uint8_t *decrypted = signed_secret_key_decrypt(signed_sk, encrypted, &len);
    if (decrypted == NULL) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);    
        return -1;
    }
    printf("decrypted (should be omar): %s", (char*)decrypted);
    public_key_free(pk);
    signature_free(sig);
    secret_key_free(sk);
    signed_secret_key_free(signed_sk);
    signature_free(deserialized);
    ptr_free(serialized);
    ptr_free(encrypted);
    ptr_free(decrypted);
}
