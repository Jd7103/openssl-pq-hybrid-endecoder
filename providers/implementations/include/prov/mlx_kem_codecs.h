/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_MLX_KEM_CODECS_H
#define OSSL_MLX_KEM_CODECS_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/bio.h>
#include "prov/mlx_kem.h"
#include "prov/provider_ctx.h"

#define MLX_XWING_SPKI_OVERHEAD 24
typedef struct {
    const uint8_t asn1_prefix[MLX_XWING_SPKI_OVERHEAD];
} MLX_SPKI_FMT;

typedef struct {
    const char *p8_name; /* Format name */
    size_t p8_bytes; /* Total P8 encoding length */
    int p8_shift; /* 4 - (top-level tag + len) */
    uint32_t p8_magic; /* The tag + len value */
    uint16_t seed_magic; /* Interior tag + len for the seed */
    size_t seed_offset; /* Seed offset from start */
    size_t seed_length; /* Seed bytes */
    uint32_t priv_magic; /* Interior tag + len for the key */
    size_t priv_offset; /* Key offset from start */
    size_t priv_length; /* Key bytes */
    size_t pub_offset; /* Pubkey offset */
    size_t pub_length; /* Pubkey bytes */
} MLX_PKCS8_FMT;

typedef struct {
    const MLX_SPKI_FMT *spkifmt;
    const MLX_PKCS8_FMT *p8fmt;
} MLX_CODEC;

#define MLX_NUM_PKCS8_FORMATS 1
typedef struct {
    const MLX_PKCS8_FMT *fmt;
    int pref;
} MLX_PKCS8_FMT_PREF;

MLX_PKCS8_FMT_PREF *
ossl_mlx_pkcs8_fmt_order(const char *algorithm_name,
    const MLX_PKCS8_FMT *p8fmt,
    const char *direction, const char *formats);

MLX_KEY *ossl_mlx_kem_d2i_PUBKEY(const uint8_t *pubenc, int publen,
    int vtable_idx, PROV_CTX *provctx,
    const char *propq);

MLX_KEY *ossl_mlx_kem_d2i_PKCS8(const uint8_t *prvenc, int prvlen,
    int vtable_idx, PROV_CTX *provctx,
    const char *propq);

int ossl_mlx_kem_i2d_pubkey(const MLX_KEY *key, unsigned char **out);
int ossl_mlx_kem_parse_public_key(const uint8_t *in, size_t len, MLX_KEY *key);

int ossl_mlx_kem_i2d_prvkey(const MLX_KEY *key, uint8_t **out,
    PROV_CTX *provctx, const char *formats);

int ossl_mlx_kem_key_to_text(BIO *out, const MLX_KEY *key, int selection);

#endif /* OSSL_MLX_KEM_CODECS_H */