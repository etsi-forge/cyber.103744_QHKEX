/*
    This file implements ETSI TC CYBER QSC Quantum-safe Hybrid Key Exchanges
    (Version 1.1.1)

    This is not intended for production use.  It is intended to be a reference
    implementation for test vectors for the specification.

    It uses OpenSSL version 1.1.1d libcrypto.

    gcc -Wall -o etsi-hkex-test main.c qshkex.c -lcrypto
    ./etsi-hkex-test

    Copyright 2020 ETSI. All rights reserved
    SPDX-License-Identifier: BSD-3-Clause
*/

#include "qshkex.h"

/* Memory helper functions to handle null values */
static inline void *my_memcpy(void *dst, const void *src, size_t byte_len)
{
    if (src == NULL || dst == NULL) {
        return dst;
    }
    return memcpy(dst, src, byte_len);
}

/*  Implements the kdf context formatting function f, see Section 7.2  */
int f_function(const EVP_MD *md_type, uint8_t *kdf_context, uint32_t *clength, const uint8_t *arg1,
               const uint32_t a1length, const uint8_t *arg2, const uint32_t a2length, const uint8_t *arg3,
               const uint32_t a3length)
{
    int         rval = FAILURE;
    uint32_t    length;
    EVP_MD_CTX *mdctx = NULL;

    do {
        if ((md_type == NULL) || (kdf_context == NULL) || (clength == NULL)) {
            break;
        }
        if (((a1length) && (arg1 == NULL)) || ((a2length) && (arg2 == NULL)) || ((a3length) && (arg3 == NULL))) {
            break;
        }
        if ((mdctx = EVP_MD_CTX_new()) == NULL) {
            break;
        }
        if (EVP_DigestInit(mdctx, md_type) != 1) {
            break;
        }
        length = htonl(a1length);
        if (EVP_DigestUpdate(mdctx, &length, sizeof(length)) != 1) {
            break;
        }
        if (EVP_DigestUpdate(mdctx, arg1, a1length) != 1) {
            break;
        }
        length = htonl(a2length);
        if (EVP_DigestUpdate(mdctx, &length, sizeof(length)) != 1) {
            break;
        }
        if (EVP_DigestUpdate(mdctx, arg2, a2length) != 1) {
            break;
        }
        length = htonl(a3length);
        if (EVP_DigestUpdate(mdctx, &length, sizeof(length)) != 1) {
            break;
        }
        if (EVP_DigestUpdate(mdctx, arg3, a3length) != 1) {
            break;
        }
        if (EVP_DigestFinal_ex(mdctx, kdf_context, clength) != 1) {
            break;
        }
        rval = SUCCESS;
    } while (0);
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return rval;
}
/*  Implements the HMAC prf function from Section 7.3.2  */
int prf_hmac(const EVP_MD *md_type, uint8_t *output, uint32_t *olength, const uint8_t *secret, const uint8_t slength,
             const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
             const uint8_t *MBi, const uint32_t mbilength)
{
    int         rval    = FAILURE;
    uint32_t    clength = MAX_DIGEST_BYTE_LEN;
    uint8_t     context[MAX_DIGEST_BYTE_LEN];
    size_t      outlen = MAX_DIGEST_BYTE_LEN;
    EVP_MD_CTX *mdctx  = NULL;
    EVP_PKEY *  pkey   = NULL;

    do {
        if ((md_type == NULL) || (output == NULL) || (olength == NULL)) {
            break;
        }
        if (((slength) && (secret == NULL)) || ((kilength) && (ki == NULL))) {
            break;
        }
        if (((mailength) && (MAi == NULL)) || ((mbilength) && (MBi == NULL))) {
            break;
        }
        if (f_function(md_type, context, &clength, ki, kilength, MAi, mailength, MBi, mbilength)) {
            break;
        }
        if ((mdctx = EVP_MD_CTX_new()) == NULL) {
            break;
        }
        if ((pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, slength)) == NULL) {
            break;
        }
        if (EVP_DigestSignInit(mdctx, NULL, md_type, NULL, pkey) != 1) {
            break;
        }
        if (EVP_DigestSignUpdate(mdctx, context, clength) != 1) {
            break;
        }
        outlen = *olength;
        if (EVP_DigestSignFinal(mdctx, output, &outlen) != 1) {
            break;
        }
        *olength = (uint32_t)outlen;
        rval     = SUCCESS;
    } while (0);
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return rval;
}
/*  Implements the HMAC KDF function from Section 7.4.2   */
int kdf(const EVP_MD *md_type, uint8_t *key_material, uint32_t *klength, const uint8_t *secret, const uint32_t slength,
        const uint8_t *label, const uint32_t llength, const uint8_t *context, const uint32_t clength)
{
    int           rval = FAILURE;
    EVP_PKEY_CTX *pctx = NULL;
    size_t        keylen;

    do {
        if ((md_type == NULL) || (key_material == NULL) || (klength == NULL) || (secret == NULL)) {
            break;
        }
        if (((llength) && (label == NULL)) || ((clength) && (context == NULL))) {
            break;
        }
        if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL) {
            break;
        }
        if (EVP_PKEY_derive_init(pctx) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md_type) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, label, (int)llength) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)slength) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, context, (int)clength) != 1) {
            break;
        }
        keylen = *klength;
        if (EVP_PKEY_derive(pctx, key_material, &keylen) != 1) {
            break;
        }
        *klength = (uint32_t)keylen;
        rval     = SUCCESS;
    } while (0);
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rval;
}
/*  Implements the function Concatenation KDF from Section 8.2   */
int hkex_concat(const EVP_MD *md_type, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *context, const uint32_t clength, const uint8_t *label,
                const uint32_t llength)
{
    int      rval = FAILURE;
    uint8_t  secrets[MAX_SECRETS_BYTE_LEN];
    uint8_t  kdf_context[MAX_DIGEST_BYTE_LEN];
    uint32_t kmlength, slength, kdfclength;
    uint64_t total_size;
    do {
        if ((md_type == NULL) || (key_material == NULL) || (k1 == NULL) || (k2 == NULL) || (MA == NULL) ||
            (MB == NULL)) {
            break;
        }
        if (((llength) && (label == NULL)) || ((clength) && (context == NULL)) || ((plength) && (psk == NULL))) {
            break;
        }
        total_size = plength + k1length + k2length;
        if (total_size > MAX_SECRETS_BYTE_LEN) {
            break;
        }
        kdfclength = MAX_DIGEST_BYTE_LEN;
        if (f_function(md_type, kdf_context, &kdfclength, context, clength, MA, malength, MB, mblength)) {
            break;
        }
        my_memcpy(secrets, psk, plength);
        my_memcpy(secrets + plength, k1, k1length);
        my_memcpy(secrets + plength + k1length, k2, k2length);
        slength  = plength + k1length + k2length;
        kmlength = klength;
        if (kdf(md_type, key_material, &kmlength, secrets, slength, label, llength, kdf_context, kdfclength)) {
            break;
        }
        rval = SUCCESS;
    } while (0);
    return rval;
}
/* Implements the one round of the function Cascading KDF from Section 8.3 */
int hkex_cascade(const EVP_MD *md_type, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                 const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                 const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                 const uint8_t *MBi, const uint32_t mbilength, const uint8_t *contexti, const uint32_t cilength,
                 const uint8_t *labeli, const uint32_t lilength)
{
    int      rval = FAILURE;
    uint8_t  rsecret[MAX_DIGEST_BYTE_LEN];
    uint8_t  output[MAX_KEY_MATERIAL_BYTE_LEN + MAX_DIGEST_BYTE_LEN];
    uint32_t olength, rlength = MAX_DIGEST_BYTE_LEN;
    uint64_t osize;

    do {
        if ((md_type == NULL) || (chain_secret == NULL) || (key_material == NULL) || (ki == NULL) || (MAi == NULL) ||
            (MBi == NULL)) {
            break;
        }
        if (((pcslength) && (previous_chain_secret == NULL)) || ((cilength) && (contexti == NULL)) ||
            ((lilength) && (labeli == NULL))) {
            break;
        }
        if ((cslength > MAX_DIGEST_BYTE_LEN) || (klength > MAX_KEY_MATERIAL_BYTE_LEN)) {
            break;
        }
        osize = cslength + klength;
        if (osize > sizeof(output)) {
            break;
        }
        if (prf_hmac(md_type, rsecret, &rlength, previous_chain_secret, pcslength, ki, kilength, MAi, mailength, MBi,
                     mbilength)) {
            break;
        }
        olength = (uint32_t)osize;
        if (kdf(md_type, output, &olength, rsecret, rlength, labeli, lilength, contexti, cilength)) {
            break;
        }
        if (olength != (uint32_t)osize) {
            break;
        }
        my_memcpy(chain_secret, output, cslength);
        my_memcpy(key_material, output + cslength, klength);
        OPENSSL_cleanse(output, sizeof(output));
        rval = SUCCESS;
    } while (0);
    return rval;
}
