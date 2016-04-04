//
//  pdcrypto.c
//  pdcrypto
//
//  Created by rafirafi on 3/17/16.
//  Copyright (c) 2016 rafirafi. All rights reserved.
//
//  minimal crypto needed to boot puredarwin (darwin 14.5) to userland without panic
//  only reimplement the crypto moved out from xnu to corecrypto
//  only use the part of the api available to xnu
//  only intended to be used with a puredarwin build

#include <mach/mach_types.h>
#include <sys/systm.h>

#include <libkern/crypto/register_crypto.h>
#include "pdcrypto_digest_init.h"
#include "pdcrypto_digest_update.h"
#include "pdcrypto_dummy.h"

kern_return_t pdcrypto_start(kmod_info_t * ki, void *d);
kern_return_t pdcrypto_stop(kmod_info_t *ki, void *d);

extern const struct ccdigest_info pdcmd5_di;
extern const struct ccdigest_info pdcsha1_di;
extern const struct ccmode_ecb pdcaes_ecb_encrypt;
extern const struct ccmode_ecb pdcaes_ecb_decrypt;
extern const struct ccmode_cbc pdcaes_cbc_encrypt;
extern const struct ccmode_cbc pdcaes_cbc_decrypt;

const struct crypto_functions pdcrypto_internal_functions = {
    .ccdigest_init_fn = pdcdigest_init,
    .ccdigest_update_fn = pdcdigest_update,
    .ccmd5_di = &pdcmd5_di,
    .ccsha1_di = &pdcsha1_di,

    .ccdigest_final_fn = pdcdigest_final_fn_dummy,
    .ccdigest_fn = pdcdigest_fn_dummy,
    .ccsha256_di = &pdcsha256_di_dummy,
    .ccsha384_di = &pdcsha384_di_dummy,
    .ccsha512_di = &pdcsha512_di_dummy,
    .cchmac_init_fn = pdchmac_init_fn_dummy,
    .cchmac_update_fn = pdchmac_update_fn_dummy,
    .cchmac_final_fn = pdchmac_final_fn_dummy,
    .cchmac_fn = pdchmac_fn_dummy,
    .ccaes_ecb_encrypt = &pdcaes_ecb_encrypt,
    .ccaes_ecb_decrypt = &pdcaes_ecb_decrypt,
    .ccaes_cbc_encrypt = &pdcaes_cbc_encrypt,
    .ccaes_cbc_decrypt = &pdcaes_cbc_decrypt,
    .ccaes_xts_encrypt = &pdcaes_xts_encrypt_dummy,
    .ccaes_xts_decrypt = &pdcaes_xts_decrypt_dummy,
    .ccaes_gcm_encrypt = &pdcaes_gcm_encrypt_dummy,
    .ccaes_gcm_decrypt = &pdcaes_gcm_decrypt_dummy,
    .ccdes_ecb_encrypt = &pdcdes_ecb_encrypt_dummy,
    .ccdes_ecb_decrypt = &pdcdes_ecb_decrypt_dummy,
    .ccdes_cbc_encrypt = &pdcdes_cbc_encrypt_dummy,
    .ccdes_cbc_decrypt = &pdcdes_cbc_decrypt_dummy,
    .cctdes_ecb_encrypt = &pdctdes_ecb_encrypt_dummy,
    .cctdes_ecb_decrypt = &pdctdes_ecb_decrypt_dummy,
    .cctdes_cbc_encrypt = &pdctdes_cbc_encrypt_dummy,
    .cctdes_cbc_decrypt = &pdctdes_cbc_decrypt_dummy,
    .ccrc4_info = &pdcrc4_info_dummy,
    .ccblowfish_ecb_encrypt = &pdcblowfish_ecb_encrypt_dummy,
    .ccblowfish_ecb_decrypt = &pdcblowfish_ecb_decrypt_dummy,
    .cccast_ecb_encrypt = &pdccast_ecb_encrypt_dummy,
    .cccast_ecb_decrypt = &pdccast_ecb_decrypt_dummy,
    .ccdes_key_is_weak_fn = pdcdes_key_is_weak_fn_dummy,
    .ccdes_key_set_odd_parity_fn = pdcdes_key_set_odd_parity_fn_dummy,
    .ccpad_xts_encrypt_fn = pdcpad_xts_encrypt_fn_dummy,
    .ccpad_xts_decrypt_fn = pdcpad_xts_decrypt_fn_dummy
};

kern_return_t pdcrypto_start(__unused kmod_info_t * ki, __unused void *d)
{
    int ret = register_crypto_functions((crypto_functions_t)&pdcrypto_internal_functions);
    if (ret == -1) {
        printf("%s g_crypto_funcs already loaded\n", __func__);
    } else {
        printf("%s register_crypto_functions ok\n", __func__);
    }
    return KERN_SUCCESS;
}

kern_return_t pdcrypto_stop(__unused kmod_info_t *ki, __unused void *d)
{
    return KERN_FAILURE;
}
