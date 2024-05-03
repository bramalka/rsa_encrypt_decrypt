#include "rsa_2048.h"
#include <stdio.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"

mbedtls_pk_context pk;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

int hex_to_base64(const char *hex_data, size_t hex_len, char *base64_buffer, size_t base64_buffer_size) {
    int ret = 0;
    size_t binary_len = hex_len / 2; // Each hex character represents 4 bits, so divide by 2 to get the binary length

    // Allocate memory for binary buffer
    unsigned char binary_buffer[binary_len];
    memset(binary_buffer, 0, binary_len);

    // Convert hex string to binary
    for (size_t i = 0; i < binary_len; ++i) {
        sscanf(&hex_data[i * 2], "%2hhx", &binary_buffer[i]);
    }

    // Encode binary data as Base64
    size_t base64_len;
    ret = mbedtls_base64_encode((unsigned char *)base64_buffer, base64_buffer_size, &base64_len, binary_buffer, binary_len);
    if (ret != 0) {
        printf("Base64 encoding failed: -0x%04X\n", -ret);
        return ret;
    }

    return 0;
}

void mbedtls_init() {
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
}

void mbedtls_cleanup() {
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int rsa_encrypt(const char *plaintext, size_t plaintext_len, unsigned char *encrypted, char *base64_ret_encrypted, const char *public_key_str) { //

    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)public_key_str, strlen(public_key_str) + 1);
    if (ret != 0) {
        // printf("Failed to parse public key: -0x%04X\n", -ret);
        return ret;
    }
    // printf("Success to parse public key: -0x%04X\n", -ret);

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, plaintext_len, (const unsigned char *)plaintext, encrypted);
    if (ret != 0) {
        // printf("Encryption failed: -0x%04X\n", -ret);
    } else {
        // printf("Success to encrypt using public key: -0x%04X\n", -ret);

        char encrypted_hex[MBEDTLS_MPI_MAX_SIZE * 2];
        for (size_t i = 0; i < mbedtls_mpi_size(&rsa->N); ++i) {
            snprintf(&encrypted_hex[i * 2], 3, "%02X", encrypted[i]);
        }

        ret = hex_to_base64(encrypted_hex, mbedtls_mpi_size(&rsa->N) * 2, base64_ret_encrypted, MBEDTLS_MPI_MAX_SIZE * 2);
        if (ret != 0) {
            // printf("Conversion to Base64 failed: -0x%04X\n", -ret);
            return ret;
        }
    }

    mbedtls_cleanup();

    return ret;
}

int rsa_decrypt(const unsigned char *cyphertext, size_t output_len, unsigned char *output,const char *private_key_str) { 
    int ret = 0;    

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)private_key_str, strlen(private_key_str) + 1, NULL, 0);
    if (ret != 0) {
        // printf("Failed to parse private key: -0x%04X\n", -ret);
        return ret;
    }
    // printf("Success to parse private key: -0x%04X\n", -ret);

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    ret = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &output_len, cyphertext, output, MBEDTLS_MPI_MAX_SIZE);
    if (ret != 0) {
        // printf("Decryption failed: -0x%04X\n", -ret);
    } else {
        // printf("Success to decrypt using private key: -0x%04X\n", -ret);
    }

    mbedtls_cleanup();

    return ret;
}

