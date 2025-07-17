/*
    This file implements ETSI TC CYBER QSC Quantum-safe Hybrid Key Exchanges
    (Version 1.1.1)

    This is not intended for production use.  It is intended to be a reference
    implementation for test vectors for the specification.

    It uses OpenSSL version 3.4.0 libcrypto.

    gcc -Wall -o etsi-hkex-test main.c crypto.c qshkex.c -lcrypto -loqs
    ./etsi-hkex-test

    Copyright 2020 ETSI. All rights reserved
    SPDX-License-Identifier: BSD-3-Clause
*/

#include "crypto.h"
#include "qshkex.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include <oqs/oqs.h>
#include <oqs/rand.h>

// Custom deterministic RNG function
void deterministic_randombytes(unsigned char *random_array, size_t bytes_to_generate) 
{   
    uint32_t out_len = SEED_LEN_BYTES;
    ascii_hex_strings_to_uint8(random_array, &out_len, 1, deterministic_seed[current_seed_index]);
    if (out_len != bytes_to_generate) {
        return;
    }
    current_seed_index++;
}

int test_qhkex_derand_ecdh(const int curve, const char *priv_dataA, const char *peerB, uint8_t *pubA, size_t *PA1length, uint8_t *pubB, size_t *PB1length, uint8_t *ss, uint32_t *ss_len)
{
    int            rval = FAILURE;
    BIGNUM         *privA = NULL, *x = NULL;
    EC_POINT       *peer_pointB = NULL, *shared_secret_point = NULL, *pub_keyA = NULL;
    EC_GROUP       *groupA = NULL;
    EVP_PKEY_CTX   *ctxA = NULL;
    EVP_PKEY       *pkeyA = NULL, *pkeyB = NULL;
    size_t         field_len, ss_lenA;
    uint8_t        shared_secretA[X448_KEY_LEN_BYTES];
    uint8_t        hex_private_keyA[X448_KEY_LEN_BYTES];
    uint8_t        pubA_cpy[MAX_KEY_BYTE_LEN], pubB_cpy[MAX_KEY_BYTE_LEN];
    uint8_t        hex_exp_shared[MAX_KEY_BYTE_LEN];

    do {
       if (curve == EVP_PKEY_X25519 || curve == EVP_PKEY_X448) {
            field_len = X25519_KEY_LEN_BYTES;
            if (curve == EVP_PKEY_X448) {
                field_len = X448_KEY_LEN_BYTES;
            }
            for (int i = 0; i < field_len; i++) {
                sscanf(&priv_dataA[i * 2], "%2hhx", &hex_private_keyA[i]);
            }
            if (!(pkeyA = EVP_PKEY_new_raw_private_key(curve, NULL, hex_private_keyA, field_len))) {
                break;
            }
            if (EVP_PKEY_get_raw_public_key(pkeyA, pubA, &field_len) <= 0) {
                break;
            }
            *PA1length = field_len;
            for (int i = 0; i < field_len; i++) {
                sscanf(&peerB[i * 2], "%2hhx", &pubB[i]);
            }
            if(!(pkeyB = EVP_PKEY_new_raw_public_key(curve, NULL, pubB, field_len))) {
                break;
            }
            *PB1length = field_len;
            if (!(ctxA = EVP_PKEY_CTX_new(pkeyA, NULL))) {
                break;
            }
            if (EVP_PKEY_derive_init(ctxA) <= 0) {
                break;
            }
            if (EVP_PKEY_derive_set_peer(ctxA, pkeyB) <= 0) {
                break;
            }
            ss_lenA = field_len;
            if (EVP_PKEY_derive(ctxA, shared_secretA, &ss_lenA) <= 0) {
                break;
            }
            memcpy(ss, shared_secretA, ss_lenA); 
            *ss_len = ss_lenA;
            ascii_hex_strings_to_uint8(hex_exp_shared, (uint32_t *)&field_len, 1, strk1[current_seed_index/2]);
            if (memcmp(ss, hex_exp_shared, field_len) != 0) {
                    break;
            }
            rval = SUCCESS;
        } else {
            if (BN_hex2bn(&privA, priv_dataA) <= 0) {
                break;
            }
            if (!(groupA = EC_GROUP_new_by_curve_name(curve))) {
                break;
            }
            if (!(pub_keyA = EC_POINT_new(groupA))) {
                break;
            }
            if (!EC_POINT_mul(groupA, pub_keyA, privA, NULL, NULL, NULL)) {
                break;
            }
            if (!EC_POINT_point2oct(groupA, pub_keyA, POINT_CONVERSION_UNCOMPRESSED, pubA_cpy, MAX_KEY_BUF_BYTES, NULL)) {
                break;
            }
            if (!(peer_pointB = EC_POINT_hex2point(groupA, peerB, NULL, NULL))) {
                break;
            }
            if (!EC_POINT_point2oct(groupA, peer_pointB, POINT_CONVERSION_UNCOMPRESSED, pubB_cpy, MAX_KEY_BUF_BYTES, NULL)) {
                break;
            }
            if (!(shared_secret_point = EC_POINT_new(groupA))) {
                break;
            }
            if (!EC_POINT_mul(groupA, shared_secret_point, NULL, peer_pointB, privA, NULL)) {
                break;
            }
            if (!(x = BN_new())) {
                break;
            }
            if (!EC_POINT_get_affine_coordinates(groupA, shared_secret_point, x, NULL,  NULL)) {
                break;
            }
            if (!(field_len = EC_GROUP_get_degree(groupA)/8)) {
                break;
            }
            memcpy(pubA, pubA_cpy + 1, field_len*2);
            *PA1length = field_len*2;
            memcpy(pubB, pubB_cpy + 1, field_len*2);
            *PB1length = field_len*2;
            BN_bn2bin(x, ss);
            *ss_len = field_len;
            ascii_hex_strings_to_uint8(hex_exp_shared, (uint32_t *)&field_len, 1, strk1[current_seed_index/2]);
            if (memcmp(ss, hex_exp_shared, field_len) != 0) {
                    break;
            }
            rval = SUCCESS;
            }   
    } while (0);
    if (privA) {
        BN_free(privA);
    }
    if (x) {
        BN_free(x);
    }
    if (peer_pointB) {
        EC_POINT_free(peer_pointB);
    }
    if (shared_secret_point) {
        EC_POINT_free(shared_secret_point);
    }
    if (pub_keyA) {
        EC_POINT_free(pub_keyA);
    }
    if (groupA) {
        EC_GROUP_free(groupA);
    }
    if (ctxA) {
        EVP_PKEY_CTX_free(ctxA);
    }
    if (pkeyA) {
        EVP_PKEY_free(pkeyA);
    }
    if (pkeyB) {
        EVP_PKEY_free(pkeyB);
    }
    return rval;
}

int test_qhkex_derand_mlkem(const char * alg_name, uint8_t *pubA, size_t *PA2length, uint8_t *ctB, size_t *CTB2length, uint8_t *ss, uint32_t *ss_len)
{
    int       rval = FAILURE;
    OQS_KEM   *kem;
    uint8_t   sk[OQS_KEM_ml_kem_1024_length_secret_key], sharedB[OQS_KEM_ml_kem_1024_length_shared_secret], hex_exp_shared[OQS_KEM_ml_kem_1024_length_shared_secret];
    
    do {
        OQS_randombytes_custom_algorithm(deterministic_randombytes);
        if (!(kem = OQS_KEM_new(alg_name))) {
            break;
        }
        if (OQS_KEM_keypair(kem, pubA, sk) != OQS_SUCCESS) {
            break;
        }
        *PA2length = kem->length_public_key;
        if (OQS_KEM_encaps(kem, ctB, ss, pubA) != OQS_SUCCESS) {
            break;
        }
        *CTB2length = kem->length_ciphertext;
        if (OQS_KEM_decaps(kem, sharedB, ctB, sk) != OQS_SUCCESS) {
            break;
        }
        *ss_len = OQS_KEM_ml_kem_1024_length_shared_secret;
        ascii_hex_strings_to_uint8(hex_exp_shared, ss_len, 1, strk2[current_seed_index/2 - 1]);
        if (memcmp(ss, sharedB, kem->length_shared_secret) != 0 || 
            memcmp(ss, hex_exp_shared, kem->length_shared_secret) != 0) {
                break;
        }
        rval = SUCCESS;
        } while (0);
        if (kem) {
            OQS_KEM_free(kem);
        }
    return rval;
}

int test_qhkex_rand_ecdh(int curve, uint8_t *pubA, size_t *PA1length, uint8_t *pubB, size_t *PB1length, uint8_t *ss, uint32_t *ss_len)
{
    int             rval    = FAILURE;
    EVP_PKEY_CTX    *ctxA = NULL, *ctxB = NULL;
    EVP_PKEY        *pkeyA = NULL, *pkeyB = NULL;
    uint8_t         ssB[MAX_KEY_BYTE_LEN];
    size_t          secret_lenA = 0, secret_lenB = 0;
    size_t          pubA_len = 0, pubB_len = 0;

    do {
        // Create entity A keys
        if (curve == EVP_PKEY_X25519 || curve == EVP_PKEY_X448) {
            if (!(ctxA = EVP_PKEY_CTX_new_id(curve, NULL))) {
                break;
            }
        } else {
            if (!(ctxA = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
                break;
            }
        }
        if (EVP_PKEY_keygen_init(ctxA) <= 0) {
            break;
        }
        if (curve != EVP_PKEY_X25519 || curve != EVP_PKEY_X448) {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctxA, curve) <= 0) {
                break;
            }
        }
        if (EVP_PKEY_keygen(ctxA, &pkeyA) <= 0) {
            break;
        }
        if (curve != EVP_PKEY_X25519 || curve != EVP_PKEY_X448) {
            if (EVP_PKEY_get_octet_string_param(pkeyA, "pub", pubA, MAX_KEY_BYTE_LEN, &pubA_len) <=0 ) {
                break;
            }
        } else {
            if (EVP_PKEY_get_raw_public_key(pkeyA, pubA, &pubA_len) <= 0) {
                break;
            }
        }
        *PA1length = pubA_len;

        // Create entity B keys
        if (curve == EVP_PKEY_X25519 || curve == EVP_PKEY_X448) {
            if (!(ctxB = EVP_PKEY_CTX_new_id(curve, NULL))) {
                break;
            }
        } else {
            if (!(ctxB = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
                break;
            }
        }
        if (EVP_PKEY_keygen_init(ctxB) <= 0) {
            break;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctxB, curve) <= 0) {
            break;
        }
        if (EVP_PKEY_keygen(ctxB, &pkeyB) <= 0) {
            break;
        }
        if (curve != EVP_PKEY_X25519 || curve != EVP_PKEY_X448) {
            if (EVP_PKEY_get_octet_string_param(pkeyB, "pub", pubB, MAX_KEY_BYTE_LEN, &pubB_len) <= 0) {
                break;
            }
        } else {
        if (EVP_PKEY_get_raw_public_key(pkeyB, pubB, &pubB_len) <= 0) {
                break;
            }
        }
        *PB1length = pubB_len;

        // Derive entity A shared secret
        ctxA = EVP_PKEY_CTX_new(pkeyA, NULL);
        if (!ctxA) {
            break;
        }
        if (EVP_PKEY_derive_init(ctxA) <= 0) {
             break;
        }
        if (EVP_PKEY_derive_set_peer(ctxA, pkeyB) <= 0) {
             break;
        }
        if (EVP_PKEY_derive(ctxA, NULL, &secret_lenA) <= 0) {
             break;
        }
        if (EVP_PKEY_derive(ctxA, ss, &secret_lenA) <= 0) {
             break;
        }

        // Derive entity B shared secret
        ctxB = EVP_PKEY_CTX_new(pkeyB, NULL);
        if (!ctxB) {
            break;
        }
        if (EVP_PKEY_derive_init(ctxB) <= 0) {
            break;
        }
        if (EVP_PKEY_derive_set_peer(ctxB, pkeyA) <= 0) {
            break;
        }
        if (EVP_PKEY_derive(ctxB, NULL, &secret_lenB) <= 0) {
            break;
        }
        if (EVP_PKEY_derive(ctxB, ssB, &secret_lenB) <= 0) {
            break;
        }
        // Check if entities shared secrets match
        if (memcmp(ss, ssB, secret_lenB) != 0 || (secret_lenA != secret_lenB)) {
            break;
        }
        *ss_len = secret_lenA;
        rval     = SUCCESS;
    } while (0);
    if (ctxA) {
        EVP_PKEY_CTX_free(ctxA);
    }
    if (ctxB) {
        EVP_PKEY_CTX_free(ctxB);
    }
    if (pkeyA) {
        EVP_PKEY_free(pkeyA);
    }
    if (pkeyB) {
        EVP_PKEY_free(pkeyB);
    }
    return rval;
}

int test_qhkex_rand_mlkem(const char * kem, uint8_t *pubA, size_t *PA2length, uint8_t *ctB, size_t *CTB2length, uint8_t *ss, uint32_t *ss_len)
{
    int           rval = FAILURE;
    size_t        pubA_len = OQS_KEM_ml_kem_1024_length_public_key; 
    size_t        ss_out_len = OQS_KEM_ml_kem_1024_length_shared_secret;
    size_t        ciphertext_len = OQS_KEM_ml_kem_1024_length_ciphertext;
    uint8_t          shared_secretB[OQS_KEM_ml_kem_1024_length_shared_secret];
    EVP_PKEY_CTX  *pkey_ctx = NULL, *encaps_ctx = NULL, *decaps_ctx = NULL;
    EVP_PKEY      *keypair = NULL;
    OSSL_PROVIDER *oqs_provider = NULL;
    OSSL_LIB_CTX  *libctx = NULL;

    do {
        if (!(libctx = OSSL_LIB_CTX_new())) {
            break;
        }
        if (!(oqs_provider = OSSL_PROVIDER_load(libctx, "oqsprovider"))) {
            break;
        }
        if (!(pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, kem, NULL))) {
            break;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
            break;
        }
        if (EVP_PKEY_keygen(pkey_ctx, &keypair) <= 0) {
            break;
        }
        if (EVP_PKEY_get_octet_string_param(keypair, "pub", pubA, OQS_KEM_ml_kem_1024_length_public_key, &pubA_len) <= 0) {
            break;
        }
        *PA2length = pubA_len;

        if (!(encaps_ctx = EVP_PKEY_CTX_new(keypair, NULL))) {
            break;
        }
        if (EVP_PKEY_encapsulate_init(encaps_ctx, NULL) <= 0) {
            break;
        }
        if (EVP_PKEY_encapsulate(encaps_ctx, NULL, &ciphertext_len, NULL, &ss_out_len) <= 0) {
            break;
        }
        *CTB2length = ciphertext_len;

        if (EVP_PKEY_encapsulate(encaps_ctx, ctB, &ciphertext_len, ss, &ss_out_len) <= 0) {
            break;
        }
        if (!(decaps_ctx = EVP_PKEY_CTX_new(keypair, NULL))) {
            break;
        }
        if (EVP_PKEY_decapsulate_init(decaps_ctx, NULL) <= 0) {
            break;
        }
        if (EVP_PKEY_decapsulate(decaps_ctx, shared_secretB, &ss_out_len, ctB, ciphertext_len) <= 0) {
            break;
        }
        if (memcmp(ss, shared_secretB, ss_out_len) != 0) {
            break;
        }
        *ss_len = ss_out_len;
        rval     = SUCCESS;
    } while (0);
    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (encaps_ctx) {
        EVP_PKEY_CTX_free(encaps_ctx);
    }
    if (decaps_ctx) {
        EVP_PKEY_CTX_free(decaps_ctx);  
    }
    if (keypair) {
        EVP_PKEY_free(keypair);
    }
    if (oqs_provider) {
        OSSL_PROVIDER_unload(oqs_provider);
    }
    if (libctx) {
        OSSL_LIB_CTX_free(libctx);
    }
    return rval;
}