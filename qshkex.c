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
#include <openssl/crypto.h>

/* Memory helper functions to handle null values */
void *my_memcpy(void *dst, const void *src, size_t byte_len)
{
    if (src == NULL || dst == NULL) {
        return dst;
    }
    return memcpy(dst, src, byte_len);
}
/*  Implements KDF concatenate-based formatting function, see Section 7.2.2                       */
/*  Input:           const uint8_t * arg1, arg2, arg3                                             */
/*  Input:           const uint32_t a1length, a2length, a3length                                  */
/*  Output:          uint8_t *kdf_context, uint32_t *clength                                      */
/*  Functionality:   kdf_context = arg1 || a1length || arg2 || a2length || arg3 || a3length       */
int cb_f(uint8_t *kdf_context, uint32_t *clength, const uint8_t *arg1,
               const uint32_t a1length, const uint8_t *arg2, const uint32_t a2length, const uint8_t *arg3,
               const uint32_t a3length)
{
    int         rval = FAILURE;
    uint32_t    length;

    do {
        if ((kdf_context == NULL) || (clength == NULL)) {
            break;
        }
        if (((a1length) && (arg1 == NULL)) || ((a2length) && (arg2 == NULL)) || ((a3length) && (arg3 == NULL))) {
            break;
        }

        length = htonl(a1length);
        my_memcpy(kdf_context, &length, sizeof(uint32_t));
        my_memcpy(kdf_context + sizeof(uint32_t), arg1, a1length);

        length = htonl(a2length);
        my_memcpy(kdf_context + sizeof(uint32_t) + a1length, &length, sizeof(uint32_t));
        my_memcpy(kdf_context + 2 * sizeof(uint32_t) + a1length, arg2, a2length);

        length = htonl(a3length);
        my_memcpy(kdf_context  + 2 * sizeof(uint32_t) + a1length + a2length, &length, sizeof(uint32_t));
        my_memcpy(kdf_context + 3 * sizeof(uint32_t) + a1length + a2length, arg3, a3length);

        *clength  = a1length + a2length + a3length  + 3 * sizeof(uint32_t);
        rval = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements KDF concatenate-and-hash-based formatting function, see Section 7.2.3                    */
/*  Input:           const uint8_t * arg1, arg2, arg3                                                   */
/*  Input:           const uint32_t a1length, a2length, a3length                                        */
/*  Input:           const EVP_MD *md_type                                                              */
/*  Output:          uint8_t *kdf_context, uint32_t *clength                                            */
/*  Functionality:   kdf_context = hash(arg1 || a1length || arg2 || a2length || arg3 || a3length)       */
int cahb_f(const EVP_MD *md_type, uint8_t *kdf_context, uint32_t *clength, const uint8_t *arg1,
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
/*  Implements HKDF KDF function from Section 7.4.2                                               */
/*  Input:           const EVP_MD *md_type                                                        */
/*  Input:           const uint8_t *secret, *label, *context                                      */
/*  Input:           const uint32_t slength, llength, clength                                     */
/*  Output:          uint8_t *key_material, uint32_t *klength                                     */
/*  Functionality:   key_material = HKDF(secret, label, context, length)                          */
int kdf_hkdf(const EVP_MD *md_type, uint8_t *key_material, uint32_t *klength, const uint8_t *secret, const uint32_t slength,
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
/*  Implements HMAC KDF function from Section 7.4.3                                               */
/*  Input:           const EVP_MD *md_type                                                        */
/*  Input:           const uint8_t *secret, *label, *context                                      */
/*  Input:           const uint32_t slength, llength, clength                                     */
/*  Output:          uint8_t *key_material, uint32_t *klength                                     */
/*  Functionality:   key_material = HMAC(label, secret || context)                                */
int kdf_hmac(const EVP_MD *md_type, uint8_t *key_material, uint32_t *klength, const uint8_t *secret, const uint32_t slength,
    const uint8_t *label, const uint32_t llength, const uint8_t *context, const uint32_t clength)
{
    int           rval = FAILURE;
    size_t        keylen;
    EVP_KDF       *kdf = NULL;
    EVP_KDF_CTX   *kctx = NULL;
    OSSL_PARAM    params[6], *p = params;

    do {
        if ((key_material == NULL) || (klength == NULL) || (secret == NULL)) {
            break;
        }
        if (((llength) && (label == NULL)) || ((clength) && (context == NULL))) {
            break;
        }
        kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
        kctx = EVP_KDF_CTX_new(kdf);

        *p++ = OSSL_PARAM_construct_utf8_string("mac", (char *)"HMAC", strlen("HMAC"));
        *p++ = OSSL_PARAM_construct_utf8_string("digest", (char *) EVP_MD_name(md_type), 0);

        *p++ = OSSL_PARAM_construct_octet_string("secret", (void *)secret, slength);
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)label, llength);
        *p++ = OSSL_PARAM_construct_octet_string("info", (void *)context, clength);
        *p = OSSL_PARAM_construct_end();

        keylen = *klength;
        if (EVP_KDF_derive(kctx, key_material, keylen, params) <= 0) {
            break;
        }

        *klength = keylen;
        rval     = SUCCESS;
    } while (0);
    if (kdf) {
            EVP_KDF_free(kdf);
    }
    if (kctx) {
            EVP_KDF_CTX_free(kctx);
    }
    return rval;
}
/*  Implements KMAC KDF function from Section 7.4.4                                               */
/*  Input:           const char *kmac                                                             */
/*  Input:           const uint8_t *secret, *label, *context                                      */
/*  Input:           const uint32_t slength, llength, clength                                     */
/*  Output:          uint8_t *key_material, uint32_t *klength                                     */
/*  Functionality:   key_material = KMAC#(label, counter || secret || context, length * 8, "KDF") */
/*  Functionality:   key_material = SSKDF_kmac(secret, label, context, length)                    */
int kdf_kmac(const char *kmac, uint8_t *key_material, uint32_t *klength, const uint8_t *secret, const uint32_t slength,
    const uint8_t *label, const uint32_t llength, const uint8_t *context, const uint32_t clength)
{
    int           rval = FAILURE;
    size_t        keylen;
    EVP_KDF       *kdf = NULL;
    EVP_KDF_CTX   *kctx = NULL;
    OSSL_PARAM    params[5], *p = params;

    do {
        if ((key_material == NULL) || (klength == NULL) || (secret == NULL)) {
            break;
        }
        if (((llength) && (label == NULL)) || ((clength) && (context == NULL))) {
            break;
        }
        kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
        kctx = EVP_KDF_CTX_new(kdf);

        *p++ = OSSL_PARAM_construct_utf8_string("mac", (char *)kmac, strlen(kmac));
        *p++ = OSSL_PARAM_construct_octet_string("secret", (void *)secret, slength);
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)label, llength);
        *p++ = OSSL_PARAM_construct_octet_string("info", (void *)context, clength);
        *p = OSSL_PARAM_construct_end();

        keylen = *klength;
        if (EVP_KDF_derive(kctx, key_material, keylen, params) <= 0) {
            break;
        }

        *klength = keylen;
        rval     = SUCCESS;
    } while (0);
    if (kdf) {
            EVP_KDF_free(kdf);
    }
    if (kctx) {
            EVP_KDF_CTX_free(kctx);
    }
    return rval;
}
/*  Implements HMAC PRF function from Section 7.3.2                                       */
/*  Input:           const EVP_MD *md_type                                                */
/*  Input:           const uint8_t *secret, *ki, *MAi, *MBi                               */
/*  Input:           const uint8_t slength, const uint32_t kilength, mailength, mbilength */
/*  Output:          uint8_t *output, uint32_t *olength                                   */
/*  Functionality:   context = cahb_f(ki, MAi, MBi)                                       */
/*  Functionality:   output = HMAC(secret, context)                                       */
int prf_hmac(const EVP_MD *md_type, uint8_t *output, uint32_t *olength, const uint8_t *secret, const uint8_t slength,
             const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
             const uint8_t *MBi, const uint32_t mbilength)
{
    int         rval    = FAILURE;
    uint32_t    clength = MAX_DIGEST_BYTE_LEN;
    uint8_t     context[MAX_DIGEST_BYTE_LEN];
    size_t      outlen = MAX_DIGEST_BYTE_LEN;

    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PARAM params[2], *p = params;

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
        if (cahb_f(md_type, context, &clength, ki, kilength, MAi, mailength, MBi, mbilength)) {
            break;
        }
        // Use EVP_MAC struct to allow zero length secret |slength|
        if ((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) ==  NULL) {
            break;
        }
        if ((ctx = EVP_MAC_CTX_new(mac)) == NULL) {
            break;
        }
        *p++ = OSSL_PARAM_construct_utf8_string("digest", (char *) EVP_MD_name(md_type), 0);
        *p   = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, secret, slength, params)) {
            break;
        }
        if (!EVP_MAC_update(ctx, context, clength)) {
            break;
        }
        outlen = *olength;
        if (!EVP_MAC_final(ctx, output, (size_t*) olength, outlen)) {
            break;
        }
        rval     = SUCCESS;
    } while (0);
    if (mac) {
        EVP_MAC_free(mac);
    }
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }
    return rval;
}
/*  Implements KMAC PRF function from Section 7.3.3                                       */
/*  Input:           const char *kmac                                                     */
/*  Input:           const uint8_t *secret, *ki, *MAi, *MBi                               */
/*  Input:           const uint8_t slength, const uint32_t kilength, mailength, mbilength */
/*  Output:          uint8_t *output, uint32_t *olength                                   */
/*  Functionality:   context = cb_f(ki, MAi, MBi)                                         */
/*  Functionality:   output = KMAC#(secret, context, 256/512, NULL)                       */
int prf_kmac(const char *kmac, uint8_t *output, uint32_t *olength, const uint8_t *secret, const uint8_t slength,
             const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
             const uint8_t *MBi, const uint32_t mbilength)
{
    int         rval    = FAILURE;
    uint32_t    clength = MAX_DIGEST_BYTE_LEN;
    uint8_t     context[MAX_BUFFER_SIZE];
    size_t      outlen = MAX_DIGEST_BYTE_LEN;
    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC     *mac = NULL;
    OSSL_PARAM  params[5], *p = params;

    do {
        if ((kmac == NULL) || (output == NULL) || (olength == NULL)) {
            break;
        }
        if (((slength) && (secret == NULL)) || ((kilength) && (ki == NULL))) {
            break;
        }
        if (((mailength) && (MAi == NULL)) || ((mbilength) && (MBi == NULL))) {
            break;
        }
        if (cb_f(context, &clength, ki, kilength, MAi, mailength, MBi, mbilength)) {
            break;
        }
        mac = EVP_MAC_fetch(NULL, kmac, NULL);
        if (!(ctx = EVP_MAC_CTX_new(mac))) {
            break;
        }
        outlen = *olength;
        *p++ = OSSL_PARAM_construct_int("size", (int *)olength);
        *p   = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, secret, slength, params)) {
            break;
        }
        if (!EVP_MAC_update(ctx, context, clength)){
            break;
        }
        if (!EVP_MAC_final(ctx, output, (size_t*)olength, outlen)){
            break;
        }
        rval     = SUCCESS;
    } while (0);
    if (mac) {
        EVP_MAC_free(mac);
    }
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }
    return rval;
}
/*  Implements function CatKDF from Section 8.2 using HKDF KDF as described in Section 7.4.2                      */
/*  Input:           const EVP_MD *md_type                                                                        */
/*  Input:           uint8_t *psk, *k1, *k2, *MA, *MB, *info, *label                                              */
/*  Input:           const uint32_t klength, plength, k1length, k2length, malength, mblength, clength, llength    */
/*  Output:          uint8_t *key_material                                                                        */
int hkex_concat_hkdf(const EVP_MD *md_type, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
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
        if (((llength) && (label == NULL)) || ((ilength) && (info == NULL)) || ((plength) && (psk == NULL))) {
            break;
        }
        total_size = plength + k1length + k2length;
        if (total_size > MAX_SECRETS_BYTE_LEN) {
            break;
        }
        kdfclength = MAX_DIGEST_BYTE_LEN;
        if (cahb_f(md_type, kdf_context, &kdfclength, info, ilength, MA, malength, MB, mblength)) {
            break;
        }

        my_memcpy(secrets, psk, plength);
        my_memcpy(secrets + plength, k1, k1length);
        my_memcpy(secrets + plength + k1length, k2, k2length);
        slength  = plength + k1length + k2length;
        kmlength = klength;
        if (kdf_hkdf(md_type, key_material, &kmlength, secrets, slength, label, llength, kdf_context, kdfclength)) {
            break;
        }
        rval     = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements function CatKDF from Section 8.2 using HMAC KDF as described in Section 7.4.3                      */
/*  Input:           const EVP_MD *md_type                                                                        */
/*  Input:           uint8_t *psk, *k1, *k2, *MA, *MB, *info, *label                                              */
/*  Input:           const uint32_t klength, plength, k1length, k2length, malength, mblength, clength, llength    */
/*  Output:          uint8_t *key_material                                                                        */
int hkex_concat_hmac(const EVP_MD *md_type, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
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
        if (((llength) && (label == NULL)) || ((ilength) && (info == NULL)) || ((plength) && (psk == NULL))) {
            break;
        }
        total_size = plength + k1length + k2length;
        if (total_size > MAX_SECRETS_BYTE_LEN) {
            break;
        }
        kdfclength = MAX_DIGEST_BYTE_LEN;
        if (cahb_f(md_type, kdf_context, &kdfclength, info, ilength, MA, malength, MB, mblength)) {
            break;
        }

        my_memcpy(secrets, psk, plength);
        my_memcpy(secrets + plength, k1, k1length);
        my_memcpy(secrets + plength + k1length, k2, k2length);
        slength  = plength + k1length + k2length;
        kmlength = klength;
        if (kdf_hmac(md_type, key_material, &kmlength, secrets, slength, label, llength, kdf_context, kdfclength)) {
            break;
        }
        rval     = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements function CatKDF from Section 8.2 using KMAC KDF as described in Section 7.4.4                      */
/*  Input:           const char *kmac                                                                             */
/*  Input:           uint8_t *psk, *k1, *k2, *MA, *MB, *info, *label                                              */
/*  Input:           const uint32_t klength, plength, k1length, k2length, malength, mblength, ilength, llength    */
/*  Output:          uint8_t *key_material                                                                        */
int hkex_concat_kmac(const char *kmac, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
                const uint32_t llength)
{
    int      rval = FAILURE;
    uint8_t  secrets[MAX_SECRETS_BYTE_LEN];
    uint8_t  kdf_context[MAX_BUFFER_SIZE];
    uint32_t kmlength, slength, kdfclength;
    uint64_t total_size;
    do {
        if ((key_material == NULL) || (k1 == NULL) || (k2 == NULL) || (MA == NULL) ||
            (MB == NULL)) {
            break;
        }
        if (((llength) && (label == NULL)) || ((ilength) && (info == NULL)) || ((plength) && (psk == NULL))) {
            break;
        }
        total_size = plength + k1length + k2length;
        if (total_size > MAX_SECRETS_BYTE_LEN) {
            break;
        }
        if (cb_f(kdf_context, &kdfclength, info, ilength, MA, malength, MB, mblength)) {
            break;
        }
        my_memcpy(secrets, psk, plength);
        my_memcpy(secrets + plength, k1, k1length);
        my_memcpy(secrets + plength + k1length, k2, k2length);
        slength  = plength + k1length + k2length;
        kmlength = klength;
        if (kdf_kmac(kmac, key_material, &kmlength, secrets, slength, label, llength, kdf_context, kdfclength)) {
            break;
        }
        rval     = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements function CasKDF from Section 8.3 using HKDF KDF and HMAC PRF as described in Sections 7.4.2 and 7.3.2    */
/*  Input:           const EVP_MD *md_type                                                                              */
/*  Input:           uint8_t *previous_chain_secret, *ki, *MAi, *MBi, infoi, *labeli                                    */
/*  Input:           const uint32_t cslength, klength, pcslength, kilength, mailength, mbilength, iilength, lilength    */
/*  Output:          uint8_t *chain_secret, *key_material                                                               */
int hkex_cascade_hkdf(const EVP_MD *md_type, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                 const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                 const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                 const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
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
        if (((pcslength) && (previous_chain_secret == NULL)) || ((iilength) && (infoi == NULL)) ||
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
        if (kdf_hkdf(md_type, output, &olength, rsecret, rlength, labeli, lilength, infoi, iilength)) {
            break;
        }
        if (olength != (uint32_t)osize) {
            break;
        }
        my_memcpy(chain_secret, output, cslength);
        my_memcpy(key_material, output + cslength, klength);
        OPENSSL_cleanse(output, sizeof(output));
        rval     = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements function CasKDF from Section 8.3 using HMAC KDF and HMAC PRF as described in Sections 7.4.3 and 7.3.2    */
/*  Input:           const EVP_MD *md_type                                                                              */
/*  Input:           uint8_t *previous_chain_secret, *ki, *MAi, *MBi, infoi, *labeli                                    */
/*  Input:           const uint32_t cslength, klength, pcslength, kilength, mailength, mbilength, iilength, lilength    */
/*  Output:          uint8_t *chain_secret, *key_material                                                               */
int hkex_cascade_hmac(const EVP_MD *md_type, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                 const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                 const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                 const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
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
        if (((pcslength) && (previous_chain_secret == NULL)) || ((iilength) && (infoi == NULL)) ||
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
        if (kdf_hmac(md_type, output, &olength, rsecret, rlength, labeli, lilength, infoi, iilength)) {
            break;
        }
        if (olength != (uint32_t)osize) {
            break;
        }
        my_memcpy(chain_secret, output, cslength);
        my_memcpy(key_material, output + cslength, klength);
        OPENSSL_cleanse(output, sizeof(output));
        rval     = SUCCESS;
    } while (0);
    return rval;
}
/*  Implements function CasKDF from Section 8.3 using KMAC KDF and KMAC PRF as described in Sections 7.4.4 and 7.3.3    */
/*  Input:           const char *kmac                                                                                   */
/*  Input:           uint8_t *previous_chain_secret, *ki, *MAi, *MBi, infoi, *labeli                                    */
/*  Input:           const uint32_t cslength, klength, pcslength, kilength, mailength, mbilength, iilength, lilength    */
/*  Output:          uint8_t *chain_secret, *key_material                                                               */
int hkex_cascade_kmac(const char *kmac, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                 const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                 const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                 const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
                 const uint8_t *labeli, const uint32_t lilength)
{
    int      rval = FAILURE;
    uint8_t  rsecret[MAX_DIGEST_BYTE_LEN];
    uint8_t  output[MAX_KEY_MATERIAL_BYTE_LEN + MAX_DIGEST_BYTE_LEN];
    uint32_t olength;
    uint32_t rlength;
    uint64_t osize;

    do {
        if ((kmac == NULL) || (chain_secret == NULL) || (key_material == NULL) || (ki == NULL) || (MAi == NULL) ||
            (MBi == NULL)) {
            break;
        }
        if (((pcslength) && (previous_chain_secret == NULL)) || ((iilength) && (infoi == NULL)) ||
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
        rlength = cslength;
        if (prf_kmac(kmac, rsecret, &rlength, previous_chain_secret, pcslength, ki, kilength, MAi, mailength, MBi,
                     mbilength)) {
            break;
        }
        olength = (uint32_t)osize;
        if (kdf_kmac(kmac, output, &olength, rsecret, rlength, labeli, lilength, infoi, iilength)) {
            break;
        }
        if (olength != (uint32_t)osize) {
            break;
        }
        my_memcpy(chain_secret, output, cslength);
        my_memcpy(key_material, output + cslength, klength);
        OPENSSL_cleanse(output, sizeof(output));
        rval     = SUCCESS;
    } while (0);
    return rval;
}