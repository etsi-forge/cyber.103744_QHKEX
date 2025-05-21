/*
    Header file for a reference implementation of
    ETSI TC CYBER QSC Quantum-safe Hybrid Key Exchanges (Version 1.1.1)

    This is not intended for production use.  It is intended to be a reference
    implementation for test vectors for the specification.

    Copyright 2020 ETSI. All rights reserved
    SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _QS_H_CRYPTO_KEX_H_
#define _QS_H_CRYPTO_KEX_H_

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include "qshkex.h"

#define SEED_LEN_BYTES             64
#define X25519_KEY_LEN_BYTES       32
#define X448_KEY_LEN_BYTES         56
#define MAX_KEY_BUF_BYTES          128

extern int current_seed_index;
extern const char *deterministic_seed[];
extern const char *strk1[];
extern const char *strk2[];

int test_qhkex_derand_ecdh(const int curve, const char *priv_dataA, const char *peerB, 
                        uint8_t *pubA, size_t *PA1length, uint8_t *pubB, size_t *PB1length, 
                        uint8_t *ss, uint32_t *ss_len);
int test_qhkex_derand_mlkem(const char * alg_name, uint8_t *pubA, size_t *PA2length, 
                        uint8_t *ctB, size_t *CTB2length, uint8_t *ss, uint32_t *ss_len);
int test_qhkex_rand_ecdh(int curve, uint8_t *pubA, size_t *PA1length, 
                        uint8_t *pubB, size_t *PB1length, uint8_t *ss, uint32_t *ss_len);
int test_qhkex_rand_mlkem(const char * kem, uint8_t *pubA, size_t *PA2length, 
                        uint8_t *ctB, size_t *CTB2length, uint8_t *ss, uint32_t *ss_len);
#endif /*_QS_H_CRYPTO_KEX_H_*/
