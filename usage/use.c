#include "crpgp.h"
#include <stdio.h>

int main() {
    struct SecretKeyParams *builder = signature_config_builder_new();
    param_set_version(builder, V2);    
    param_set_primary_user_id(builder, "Omar Elawady <elawadio@incubaid.com>");    
}
