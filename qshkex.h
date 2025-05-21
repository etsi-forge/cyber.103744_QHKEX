/*
    Header file for a reference implementation of
    ETSI TC CYBER QSC Quantum-safe Hybrid Key Exchanges (Version 1.1.1)

    This is not intended for production use.  It is intended to be a reference
    implementation for test vectors for the specification.

    Copyright 2020 ETSI. All rights reserved
    SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _QS_H_KEX_H_
#define _QS_H_KEX_H_

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#define SUCCESS                   (0)
#define FAILURE                   (-1)
#define MAX_DIGEST_BYTE_LEN       64
#define MAX_SECRETS_BYTE_LEN      256
#define MAX_KEY_MATERIAL_BYTE_LEN 128

#define MAX_BUFFER_SIZE             4096
#define MAX_LABEL_BYTE_LEN          64
#define MAX_KEY_BYTE_LEN            128
#define MAX_LABEL_LEN               32
#define KMAC128_OUT_BYTE_LENGTH     32
#define KMAC256_OUT_BYTE_LENGTH     48
#define MAX_MSG_BYTE_LEN            8192

void print_array(const char *label, const uint8_t *array, const uint32_t alength);
void ascii_hex_strings_to_uint8(uint8_t *array, uint32_t *alength, const uint32_t scount, ...);
void *my_memcpy(void *dst, const void *src, size_t byte_len);

int hkex_concat_hkdf(const EVP_MD *md_type, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
                const uint32_t llength);

int hkex_concat_hmac(const EVP_MD *md_type, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
                const uint32_t llength);

int hkex_concat_kmac(const char *kmac, uint8_t *key_material, const uint32_t klength, const uint8_t *psk,
                const uint32_t plength, const uint8_t *k1, const uint32_t k1length, const uint8_t *k2,
                const uint32_t k2length, const uint8_t *MA, const uint32_t malength, const uint8_t *MB,
                const uint32_t mblength, const uint8_t *info, const uint32_t ilength, const uint8_t *label,
                const uint32_t llength);

int hkex_cascade_hkdf(const EVP_MD *md_type, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
                const uint8_t *labeli, const uint32_t lilength);

int hkex_cascade_hmac(const EVP_MD *md_type, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
                const uint8_t *labeli, const uint32_t lilength);

int hkex_cascade_kmac(const char *kmac, uint8_t *chain_secret, const uint32_t cslength, uint8_t *key_material,
                const uint32_t klength, const uint8_t *previous_chain_secret, const uint32_t pcslength,
                const uint8_t *ki, const uint32_t kilength, const uint8_t *MAi, const uint32_t mailength,
                const uint8_t *MBi, const uint32_t mbilength, const uint8_t *infoi, const uint32_t iilength,
                const uint8_t *labeli, const uint32_t lilength);

#endif /*_QS_H_KEX_H_*/
