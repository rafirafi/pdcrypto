//
//  pdcrypto_digest_init.c
//  pdcrypto
//
//  Created by rafirafi on 3/17/16.
//  Copyright (c) 2016 rafirafi. All rights reserved.
//
//  copied from xnu, only function name was changed
//
//  xnu https://opensource.apple.com/source/xnu/xnu-2782.40.9
//  License https://opensource.apple.com/source/xnu/xnu-2782.40.9/APPLE_LICENSE

#include "pdcrypto_digest_init.h"

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccn.h>

#include <sys/systm.h>

void pdcdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx) {
    ccdigest_copy_state(di, ccdigest_state_ccn(di, ctx), di->initial_state);
    ccdigest_nbits(di, ctx) = 0;
    ccdigest_num(di, ctx) = 0;
}
