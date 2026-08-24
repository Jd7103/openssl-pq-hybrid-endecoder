/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/encoder.h"
#include "prov/ml_common_codecs.h"
#include "prov/ml_kem_codecs.h"
#include "prov/mlx_kem.h"
#include "prov/mlx_kem_codecs.h"

static const MLX_SPKI_FMT mlx_xwing_spkifmt = {{
    0x30, 0x82, 0x04, 0xd4, 0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x83, 0xe6, 0x2d, 0x81, 0xc8, 0x7a, 0x03, 0x82, 0x04,
    0xc1, 0x00
}};

static const MLX_PKCS8_FMT mlx_xwing_p8fmt[MLX_NUM_PKCS8_FORMATS] = {
    { "bare-seed",  0x0020, 4, 0,          0, 0,    0x0020, 0,          0,    0,      0,      0      },
};

#define HPKE_XWING_CODEC 0

static const MLX_CODEC codecs[1] = {
    { &mlx_xwing_spkifmt, mlx_xwing_p8fmt },
};

/* Retrieve the parameters of one of the hybrid KEMs */
static const MLX_CODEC *mlx_kem_get_codec(int evp_type)
{
    switch (evp_type) {
    case EVP_PKEY_XWING:
        return &codecs[HPKE_XWING_CODEC];
    }
    return NULL;
}

MLX_KEY *
ossl_mlx_kem_d2i_PUBKEY(const uint8_t *pubenc, int publen, int evp_type,
    PROV_CTX *provctx, const char *propq)
{
    const ECDH_VINFO *xinfo;
    const ML_KEM_VINFO *minfo;
    const MLX_CODEC *codec;
    const MLX_SPKI_FMT *vspki;
    MLX_KEY *ret;

    if ((xinfo = ossl_mlx_kem_get_vinfo(evp_type)) == NULL
        || (codec = mlx_kem_get_codec(evp_type)) == NULL)
        return NULL;
    if ((minfo = ossl_ml_kem_get_vinfo(xinfo->ml_kem_variant)) == NULL)
        return NULL;

    vspki = codec->spkifmt;
    if (publen != MLX_XWING_SPKI_OVERHEAD + (ossl_ssize_t)xinfo->pubkey_bytes
        + (ossl_ssize_t)minfo->pubkey_bytes
        || memcmp(pubenc, vspki->asn1_prefix, MLX_XWING_SPKI_OVERHEAD) != 0)
        return NULL;
    publen -= MLX_XWING_SPKI_OVERHEAD;
    pubenc += MLX_XWING_SPKI_OVERHEAD;

    if ((ret = ossl_prov_mlx_kem_new(provctx, propq, evp_type)) == NULL)
        return NULL;

    if (!ossl_mlx_kem_parse_public_key(pubenc, (size_t)publen, ret)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "error parsing %s public key from input SPKI",
            xinfo->label);
        ossl_mlx_kem_key_free(ret);
        return NULL;
    }

    return ret;
}

MLX_KEY *
ossl_mlx_kem_d2i_PKCS8(const uint8_t *prvenc, int prvlen,
    int evp_type, PROV_CTX *provctx,
    const char *propq)
{
    const ECDH_VINFO *xinfo;
    const ML_KEM_VINFO *minfo;
    const MLX_CODEC *codec;
    MLX_PKCS8_FMT_PREF *fmt_slots = NULL, *slot;
    const MLX_PKCS8_FMT *p8fmt;
    MLX_KEY *key = NULL, *ret = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    const uint8_t *buf, *pos;
    const X509_ALGOR *alg = NULL;
    int len, ptype;
    uint32_t magic;
    uint16_t seed_magic;

    /* Which Hybrid? */
    if ((xinfo = ossl_mlx_kem_get_vinfo(evp_type)) == NULL
        || (codec = mlx_kem_get_codec(evp_type)) == NULL)
        return 0;
    if ((minfo = ossl_ml_kem_get_vinfo(xinfo->ml_kem_variant)) == NULL)
        return 0;

    /* Extract the key OID and any parameters. */
    if ((p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &prvenc, prvlen)) == NULL)
        return 0;
    /* Shortest prefix is 4 bytes: seq tag/len  + octet string tag/len */
    if (!PKCS8_pkey_get0(NULL, &buf, &len, &alg, p8inf))
        goto end;
    /* Bail out early if this is some other key type. */
    if (OBJ_obj2nid(alg->algorithm) != evp_type)
        goto end;

    fmt_slots = ossl_mlx_pkcs8_fmt_order(xinfo->label, codec->p8fmt,
        "input", NULL);
    if (fmt_slots == NULL)
        goto end;

    /* Parameters must be absent. */
    X509_ALGOR_get0(NULL, &ptype, NULL, alg);
    if (ptype != V_ASN1_UNDEF) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_UNEXPECTED_KEY_PARAMETERS,
            "unexpected parameters with a PKCS#8 %s private key",
            xinfo->label);
        goto end;
    }
    if ((ossl_ssize_t)len < (ossl_ssize_t)sizeof(magic))
        goto end;

    /* Find the matching p8 info slot, that also has the expected length. */
    pos = OPENSSL_load_u32_be(&magic, buf);
    for (slot = fmt_slots; (p8fmt = slot->fmt) != NULL; ++slot) {
        if (len != (ossl_ssize_t)p8fmt->p8_bytes)
            continue;
        if (p8fmt->p8_shift == sizeof(magic)
            || (magic >> (p8fmt->p8_shift * 8)) == p8fmt->p8_magic) {
            pos -= p8fmt->p8_shift;
            break;
        }
    }
    if (p8fmt == NULL
        || (p8fmt->seed_length > 0 && p8fmt->seed_length != xinfo->ec_nSeed)
        || (p8fmt->priv_length > 0 && p8fmt->priv_length != xinfo->prvkey_bytes + minfo->prvkey_bytes)
        || (p8fmt->pub_length > 0 && p8fmt->pub_length != xinfo->pubkey_bytes + minfo->pubkey_bytes)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
            "no matching enabled %s private key input formats",
            xinfo->label);
        goto end;
    }

    if (p8fmt->seed_length > 0) {
        /* Check |seed| tag/len, if not subsumed by |magic|. */
        if (pos + sizeof(uint16_t) == buf + p8fmt->seed_offset) {
            pos = OPENSSL_load_u16_be(&seed_magic, pos);
            if (seed_magic != p8fmt->seed_magic)
                goto end;
        } else if (pos != buf + p8fmt->seed_offset) {
            goto end;
        }
        pos += xinfo->ec_nSeed;
    }
    if (p8fmt->priv_length > 0) {
        /* Check |priv| tag/len */
        if (pos + sizeof(uint32_t) == buf + p8fmt->priv_offset) {
            pos = OPENSSL_load_u32_be(&magic, pos);
            if (magic != p8fmt->priv_magic)
                goto end;
        } else if (pos != buf + p8fmt->priv_offset) {
            goto end;
        }
        pos += xinfo->prvkey_bytes + minfo->prvkey_bytes;
    }
    if (p8fmt->pub_length > 0) {
        if (pos != buf + p8fmt->pub_offset)
            goto end;
        pos += xinfo->pubkey_bytes + minfo->pubkey_bytes;
    }
    if (pos != buf + len)
        goto end;

    if ((key = ossl_prov_mlx_kem_new(provctx, propq, evp_type)) == NULL)
        goto end;

    if (p8fmt->seed_length > 0) {
        if (!ossl_mlx_kem_key_gen(key, buf + p8fmt->seed_offset,
                xinfo->ec_nSeed, 0)) {
            ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR,
                "error deriving %s private key from seed",
                xinfo->label);
            goto end;
        }
    }
    if (p8fmt->priv_length > 0) {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            (void *)(buf + p8fmt->priv_offset), p8fmt->priv_length);
        params[1] = OSSL_PARAM_construct_end();

        if (!ossl_mlx_kem_key_fromdata(key, params, 1)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                "error parsing %s private key",
                xinfo->label);
            goto end;
        }
    }
    /* Any OQS public key content is ignored */
    ret = key;

end:
    OPENSSL_free(fmt_slots);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (ret == NULL)
        ossl_mlx_kem_key_free(key);
    return ret;
}

int ossl_mlx_kem_i2d_pubkey(const MLX_KEY *key, unsigned char **out)
{
    size_t publen;

    if (!mlx_kem_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
            "no %s public key data available",
            key->xinfo->label);
        return 0;
    }
    publen = key->xinfo->pubkey_bytes + key->minfo->pubkey_bytes;

    if ((*out = OPENSSL_malloc(publen)) == NULL)
        return 0;
    if (!ossl_mlx_kem_encode_public_key(*out, publen, key)) {
        ERR_raise_data(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR,
            "error encoding %s public key",
            key->xinfo->label);
        OPENSSL_free(*out);
        return 0;
    }

    return (int)publen;
}

/* Allocate and encode PKCS#8 private key payload. */
int ossl_mlx_kem_i2d_prvkey(const MLX_KEY *key, uint8_t **out,
    PROV_CTX *provctx, const char *formats)
{
    const ECDH_VINFO *xinfo = key->xinfo;
    const ML_KEM_VINFO *minfo = key->minfo;
    const MLX_CODEC *codec;
    MLX_PKCS8_FMT_PREF *fmt_slots, *slot;
    const MLX_PKCS8_FMT *p8fmt;
    uint8_t *buf = NULL, *pos;
    size_t len;
    int have_seed = mlx_kem_have_seed(key);
    int ret = 0;

    /* Not ours to handle */
    if ((codec = mlx_kem_get_codec(xinfo->evp_type)) == NULL)
        return 0;

    if (!mlx_kem_have_prvkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY,
            "no %s private key data available",
            key->xinfo->label);
        return 0;
    }

    fmt_slots = ossl_mlx_pkcs8_fmt_order(xinfo->label, codec->p8fmt,
        "output", formats);
    if (fmt_slots == NULL)
        return 0;

    /* If we don't have a seed, skip seedful entries */
    for (slot = fmt_slots; (p8fmt = slot->fmt) != NULL; ++slot)
        if (have_seed || p8fmt->seed_length == 0)
            break;
    /* No matching table entries, give up */
    if (p8fmt == NULL
        || (p8fmt->seed_length > 0 && p8fmt->seed_length != xinfo->ec_nSeed)
        || (p8fmt->priv_length > 0 && p8fmt->priv_length != xinfo->prvkey_bytes + minfo->prvkey_bytes)
        || (p8fmt->pub_length > 0 && p8fmt->pub_length != xinfo->pubkey_bytes + minfo->pubkey_bytes)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
            "no matching enabled %s private key output formats",
            xinfo->label);
        goto end;
    }
    len = p8fmt->p8_bytes;

    if (out == NULL) {
        ret = (int)len;
        goto end;
    }

    if ((pos = buf = OPENSSL_malloc(len)) == NULL)
        goto end;

    switch (p8fmt->p8_shift) {
    case 0:
        pos = OPENSSL_store_u32_be(pos, p8fmt->p8_magic);
        break;
    case 2:
        pos = OPENSSL_store_u16_be(pos, (uint16_t)p8fmt->p8_magic);
        break;
    case 4:
        break;
    default:
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "error encoding %s private key",
            xinfo->label);
        goto end;
    }

    if (p8fmt->seed_length != 0) {
        /*
         * Either the tag/len were already included in |magic| or they require
         * us to write two bytes now.
         */
        if (pos != buf + p8fmt->seed_offset
            || !ossl_mlx_kem_encode_seed(pos, xinfo->ec_nSeed, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                "error encoding %s private key",
                xinfo->label);
            goto end;
        }
        pos += xinfo->ec_nSeed;
    }
    if (p8fmt->priv_length != 0) {
        if (pos + sizeof(uint32_t) == buf + p8fmt->priv_offset)
            pos = OPENSSL_store_u32_be(pos, p8fmt->priv_magic);
        if (pos != buf + p8fmt->priv_offset
            || !ossl_mlx_kem_encode_private_key(pos, xinfo->prvkey_bytes + minfo->prvkey_bytes, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                "error encoding %s private key",
                xinfo->label);
            goto end;
        }
        pos += xinfo->prvkey_bytes + minfo->prvkey_bytes;
    }
    /* OQS form output with tacked-on public key */
    if (p8fmt->pub_length != 0) {
        /* The OQS pubkey is never separately DER-wrapped */
        if (pos != buf + p8fmt->pub_offset
            || !ossl_mlx_kem_encode_public_key(pos, xinfo->pubkey_bytes + minfo->pubkey_bytes, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                "error encoding %s private key",
                xinfo->label);
            goto end;
        }
        pos += xinfo->pubkey_bytes + minfo->pubkey_bytes;
    }

    if (pos == buf + len) {
        *out = buf;
        ret = (int)len;
    }

end:
    OPENSSL_free(fmt_slots);
    if (ret == 0)
        OPENSSL_free(buf);
    return ret;
}

int ossl_mlx_kem_key_to_text(BIO *out, const MLX_KEY *key, int selection)
{
    uint8_t seed[64], *prvenc = NULL, *pubenc = NULL;
    size_t publen, prvlen;
    const char *type_label = NULL;
    int ret = 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    type_label = key->xinfo->label;
    publen = key->xinfo->pubkey_bytes + key->minfo->pubkey_bytes;
    prvlen = key->xinfo->prvkey_bytes + key->minfo->prvkey_bytes;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (mlx_kem_have_prvkey(key)
            || mlx_kem_have_seed(key))) {
        if (BIO_printf(out, "%s Private-Key:\n", type_label) <= 0)
            return 0;

        if (mlx_kem_have_seed(key)) {
            size_t seedlen = key->xinfo->ec_nSeed;

            if (seedlen == 0 || seedlen > sizeof(seed)
                || !ossl_mlx_kem_encode_seed(seed, seedlen, key))
                goto end;
            if (!ossl_bio_print_labeled_buf(out, "seed:", seed, seedlen))
                goto end;
        }
        if (mlx_kem_have_prvkey(key)) {
            if ((prvenc = OPENSSL_malloc(prvlen)) == NULL)
                return 0;
            if (!ossl_mlx_kem_encode_private_key(prvenc, prvlen, key))
                goto end;
            if (!ossl_bio_print_labeled_buf(out, "dk:", prvenc, prvlen))
                goto end;
        }
        ret = 1;
    }

    /* The public key is output regardless of the selection */
    if (mlx_kem_have_pubkey(key)) {
        /* If we did not output private key bits, this is a public key */
        if (ret == 0 && BIO_printf(out, "%s Public-Key:\n", type_label) <= 0)
            goto end;

        if ((pubenc = OPENSSL_malloc(publen)) == NULL
            || !ossl_mlx_kem_encode_public_key(pubenc, publen, key)
            || !ossl_bio_print_labeled_buf(out, "ek:", pubenc, publen))
            goto end;
        ret = 1;
    }

    /* If we got here, and ret == 0, there was no key material */
    if (ret == 0)
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
            "no %s key material available",
            type_label);

end:
    OPENSSL_free(pubenc);
    OPENSSL_free(prvenc);
    return ret;
}

int ossl_mlx_kem_parse_public_key(const uint8_t *in, size_t len, MLX_KEY *key)
{
    OSSL_PARAM params[2];
    if (key == NULL || mlx_kem_have_pubkey(key))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,(void *)in, len);
    params[1] = OSSL_PARAM_construct_end();

    return ossl_mlx_kem_key_fromdata(key, params, 0);
}

static int pref_cmp(const void *va, const void *vb)
{
    const MLX_PKCS8_FMT_PREF *a = va;
    const MLX_PKCS8_FMT_PREF *b = vb;
 
    if (a->pref > 0 && b->pref > 0)
        return a->pref - b->pref;
    return b->pref - a->pref;
}
 
MLX_PKCS8_FMT_PREF *
ossl_mlx_pkcs8_fmt_order(const char *algorithm_name,
    const MLX_PKCS8_FMT *p8fmt,
    const char *direction, const char *formats)
{
    MLX_PKCS8_FMT_PREF *ret;
    int i, nvalid = 0, count = 0;
    const char *fmt, *end;
    const char *sep = "\t ,";
 
    /* Reserve an extra terminal slot with fmt == NULL */
    if ((ret = OPENSSL_calloc(MLX_NUM_PKCS8_FORMATS + 1, sizeof(*ret))) == NULL)
        return NULL;

    for (i = 0; i < MLX_NUM_PKCS8_FORMATS && p8fmt[i].p8_name != NULL; ++i) {
        ret[nvalid].fmt = &p8fmt[i];
        ret[nvalid].pref = 0;
        ++nvalid;
    }
 
    /* Default to compile-time table order when none specified. */
    if (formats == NULL)
        return ret;
 
    /*
     * Formats are case-insensitive, separated by spaces, tabs or commas.
     * Duplicate formats are allowed, the first occurrence determines the order.
     */
    fmt = formats;
    do {
        if (*(fmt += strspn(fmt, sep)) == '\0')
            break;
        end = fmt + strcspn(fmt, sep);
        for (i = 0; i < nvalid; ++i) {
            /* Skip slots already selected or with a different name. */
            if (ret[i].pref > 0
                || OPENSSL_strncasecmp(ret[i].fmt->p8_name,
                       fmt, (end - fmt))
                    != 0)
                continue;
            /* First time match */
            ret[i].pref = ++count;
            break;
        }
        fmt = end;
    } while (count < nvalid);
 
    /* No formats matched, raise an error */
    if (count == 0) {
        OPENSSL_free(ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
            "no %s private key %s formats are enabled",
            algorithm_name, direction);
        return NULL;
    }
    /* Sort by preference, with 0's last; only the valid prefix of ret[] */
    qsort(ret, nvalid, sizeof(*ret), pref_cmp);
    /* Terminate the list at first unselected entry, perhaps reserved slot. */
    ret[count].fmt = NULL;
    return ret;
}
