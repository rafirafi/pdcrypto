#include "pdcrypto_dummy.h"

#include <sys/systm.h>

#include "pdcrypto_digest_final.h"

/*
 * to print what is used by xnu during boot
 */

void pdcdigest_final_fn_dummy(const struct ccdigest_info *di,
                              ccdigest_ctx_t ctx,
                              void *digest)
{
    printf("%s\n", __func__);
}

void pdcdigest_fn_dummy(const struct ccdigest_info *di,
                        unsigned long len,
                        const void *data, void *digest)
{
    printf("%s\n", __func__);
}

#include <corecrypto/ccsha2.h>

const uint32_t pdcsha256_initial_state[8] = {
    0x6A09E667UL, // A
    0xBB67AE85UL, // B
    0x3C6EF372UL, // C
    0xA54FF53AUL, // D
    0x510E527FUL, // E
    0x9B05688CUL, // F
    0x1F83D9ABUL, // G
    0x5BE0CD19UL  // H
};

static void pdcsha256_compress_dummy(ccdigest_state_t s, unsigned long nblocks, const void *data)
{
    printf("%s\n", __func__);
}

const struct ccdigest_info pdcsha256_di_dummy = {
    .output_size = CCSHA256_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,
    .block_size = CCSHA256_BLOCK_SIZE,
    .oid_size = ccoid_sha256_len,
    .oid = (unsigned char *)CC_DIGEST_OID_SHA256,
    .initial_state = pdcsha256_initial_state,
    .compress = pdcsha256_compress_dummy,
    .final = pdcdigest_final_64be
};

static void pdcsha384_compress_dummy(ccdigest_state_t s, unsigned long nblocks, const void *data)
{
    printf("%s\n", __func__);
}

const uint64_t pdcsha384_initial_state[8] = {
    0xCBBB9D5DC1059ED8, // A
    0x629A292A367CD507, // B
    0x9159015A3070DD17, // C
    0x152FECD8F70E5939, // D
    0x67332667FFC00B31, // E
    0x8EB44A8768581511, // F
    0xDB0C2E0D64F98FA7, // G
    0x47B5481DBEFA4FA4  // H
};

const struct ccdigest_info pdcsha384_di_dummy = {
    .output_size = CCSHA384_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha384_len,
    .oid = (unsigned char *)CC_DIGEST_OID_SHA384,
    .initial_state = pdcsha384_initial_state,
    .compress = pdcsha384_compress_dummy,
    .final = pdcdigest_final_64be
};


//const struct ccdigest_info pdcsha512_di_dummy;

static void pdcsha512_compress_dummy(ccdigest_state_t s, unsigned long nblocks, const void *data)
{
    printf("%s\n", __func__);
}

const uint64_t pdcsha512_initial_state[8] = {
    0x6A09E667F3BCC908, // A
    0xBB67AE8584CAA73B, // B
    0x3C6EF372FE94F82B, // C
    0xA54FF53A5F1D36F1, // D
    0x510E527FADE682D1, // E
    0x9B05688C2B3E6C1F, // F
    0x1F83D9ABFB41BD6B, // G
    0x5BE0CD19137E2179  // H
};

const struct ccdigest_info pdcsha512_di_dummy = {
    .output_size = CCSHA512_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha512_len,
    .oid = (unsigned char *)CC_DIGEST_OID_SHA512,
    .initial_state = pdcsha512_initial_state,
    .compress = pdcsha512_compress_dummy,
    .final = pdcdigest_final_64be
};

void pdchmac_init_fn_dummy(const struct ccdigest_info *di,
                           cchmac_ctx_t ctx,
                           unsigned long key_len, const void *key)
{
    printf("%s\n", __func__);
}

void pdchmac_update_fn_dummy(const struct ccdigest_info *di,
                             cchmac_ctx_t ctx,
                             unsigned long data_len,
                             const void *data)
{
    printf("%s\n", __func__);
}

void pdchmac_final_fn_dummy(const struct ccdigest_info *di,
                            cchmac_ctx_t ctx,
                            unsigned char *mac)
{
    printf("%s\n", __func__);
}

void pdchmac_fn_dummy(const struct ccdigest_info *di,
                      unsigned long key_len,
                      const void *key,
                      unsigned long data_len,
                      const void *data,
                      unsigned char *mac)
{
    printf("%s\n", __func__);
}

static void pdcmode_ecb_init_dummy(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
                                   size_t key_len, const void *key)
{
    printf("%s\n", __func__);
}

static void pdcmode_cbc_init_dummy(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                                   size_t key_len, const void *key)
{
    printf("%s\n", __func__);
}

const struct ccmode_ecb pdcaes_ecb_encrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_ecb pdcaes_ecb_decrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

static void pdcmode_aes_cbc_init_dummy(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                                       size_t key_len, const void *key)
{
    printf("%s\n", __func__);
}

const struct ccmode_cbc pdcaes_cbc_encrypt_dummy = {
    .init = pdcmode_aes_cbc_init_dummy
};

const struct ccmode_cbc pdcaes_cbc_decrypt_dummy = {
    .init = pdcmode_aes_cbc_init_dummy
};

const struct ccmode_xts pdcaes_xts_encrypt_dummy;
const struct ccmode_xts pdcaes_xts_decrypt_dummy;
const struct ccmode_gcm pdcaes_gcm_encrypt_dummy;
const struct ccmode_gcm pdcaes_gcm_decrypt_dummy;

const struct ccmode_ecb pdcdes_ecb_encrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_ecb pdcdes_ecb_decrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_cbc pdcdes_cbc_encrypt_dummy = {
    .init = pdcmode_cbc_init_dummy
};

const struct ccmode_cbc pdcdes_cbc_decrypt_dummy = {
    .init = pdcmode_cbc_init_dummy
};

const struct ccmode_ecb pdctdes_ecb_encrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_ecb pdctdes_ecb_decrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_cbc pdctdes_cbc_encrypt_dummy = {
    .init = pdcmode_cbc_init_dummy
};

const struct ccmode_cbc pdctdes_cbc_decrypt_dummy = {
    .init = pdcmode_cbc_init_dummy
};

const struct ccrc4_info pdcrc4_info_dummy;

const struct ccmode_ecb pdcblowfish_ecb_encrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_ecb pdcblowfish_ecb_decrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};


const struct ccmode_ecb pdccast_ecb_encrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};

const struct ccmode_ecb pdccast_ecb_decrypt_dummy = {
    .init = pdcmode_ecb_init_dummy
};


int pdcdes_key_is_weak_fn_dummy(void *key,
                                unsigned long  length)
{
    printf("%s\n", __func__);
    return -1;
}

void pdcdes_key_set_odd_parity_fn_dummy(void *key,
                                        unsigned long length)
{
    printf("%s\n", __func__);
}

void pdcpad_xts_decrypt_fn_dummy(const struct ccmode_xts *xts,
                                 ccxts_ctx *ctx,
                                 unsigned long nbytes,
                                 const void *in,
                                 void *out)
{
    printf("%s\n", __func__);
}

void pdcpad_xts_encrypt_fn_dummy(const struct ccmode_xts *xts,
                                 ccxts_ctx *ctx,
                                 unsigned long nbytes,
                                 const void *in,
                                 void *out)
{
    printf("%s\n", __func__);
}
