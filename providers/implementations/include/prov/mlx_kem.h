/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_MLX_KEM_H
#define OSSL_MLX_KEM_H
#pragma once

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <crypto/ml_kem.h>
#include <crypto/ecx.h>
#include <stdbool.h>
#include "prov/provider_ctx.h"

#define EVP_PKEY_XWING NID_HPKE_XWING

typedef struct ecdh_vinfo_st {
    const char *algorithm_name;
    const char *group_name;
    size_t pubkey_bytes;
    size_t prvkey_bytes;
    size_t shsec_bytes;
    int ml_kem_slot;
    int ml_kem_variant;
    size_t ec_nSeed; /* Used for HPKE keygen entropy length, zero for TLS use cases */
    const char *label;
    int evp_type;
    int kemid;
} ECDH_VINFO;

typedef struct mlx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const ML_KEM_VINFO *minfo;
    const ECDH_VINFO *xinfo;
    EVP_PKEY *mkey;
    EVP_PKEY *xkey;
    unsigned int state;
    int kemid;
    unsigned char *dk_seed;
    size_t dk_seed_len; 
} MLX_KEY;

#define ossl_mlx_kem_have_dkenc(key) ((key)->encoded_dk != NULL)

#define MLX_HAVE_NOKEYS 0
#define MLX_HAVE_PUBKEY 1
#define MLX_HAVE_PRVKEY 2

/* Both key parts have whatever the ML-KEM component has */
#define mlx_kem_have_pubkey(key) ((key)->state > 0)
#define mlx_kem_have_prvkey(key) ((key)->state > 1)
#define mlx_kem_have_seed(key) ((key)->dk_seed != NULL)

const ECDH_VINFO *ossl_mlx_kem_get_vinfo(int evp_type);

MLX_KEY *ossl_prov_mlx_kem_new(PROV_CTX *provctx, const char *propq, int evp_type);
MLX_KEY *ossl_mlx_kem_set_seed(const uint8_t *seed, size_t seedlen, MLX_KEY *key);

int ossl_mlx_kem_encode_public_key(uint8_t *out, size_t len, const MLX_KEY *key);
int ossl_mlx_kem_encode_private_key(uint8_t *out, size_t len, const MLX_KEY *key);
int ossl_mlx_kem_encode_seed(uint8_t *out, size_t len, const MLX_KEY *key);
int ossl_mlx_kem_key_fromdata(MLX_KEY *key, const OSSL_PARAM params[], int include_private);
int ossl_mlx_kem_key_gen(MLX_KEY *key, const uint8_t *ikm_or_seed, size_t ikm_or_seedlen, bool is_ikm);

void ossl_mlx_kem_key_free(void *vkey);

#endif