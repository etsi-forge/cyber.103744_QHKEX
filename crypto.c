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