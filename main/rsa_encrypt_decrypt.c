#include <stdio.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"

const char *public_key_str =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8R5i88R2+WladPnHDA4EY2hxw0jO8OG/GsiH0UvBMzW74XHa2vUVOAmh8inXB85R3DRMPdI7i+k10SdNjBLZ/oieS4pUty9ylKppmJepRrFK7uhoupTfS5Nfp4MZDRpa6LbLwudw2VOMGw9NJiMOVPWklusYUzHxFiMkv/896tZ+bDUWLSYz4A60YDooZkxs2jev7EwxXCGkIVZtgE90wRF0BC8qbLLK/w1oQPdU+RnXjv7Ykfx+3II0Iw62mjHfrsZMo6zo94lKpV8YK8XK9OVpkUjPv49s0PfCUHzEloCaIwR9mU9nhjuyog4xeO+W2nVvXN9wq61uMm1SMj7hwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const char *private_key_str = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzxHmLzxHb5aVp0+ccMDgRjaHHDSM7w4b8ayIfRS8EzNbvhcdra9RU4CaHyKdcHzlHcNEw90juL6TXRJ02MEtn+iJ5LilS3L3KUqmmYl6lGsUru6Gi6lN9Lk1+ngxkNGlrotsvC53DZU4wbD00mIw5U9aSW6xhTMfEWIyS//z3q1n5sNRYtJjPgDrRgOihmTGzaN6/sTDFcIaQhVm2AT3TBEXQELypsssr/DWhA91T5GdeO/tiR/H7cgjQjDraaMd+uxkyjrOj3iUqlXxgrxcr05WmRSM+/j2zQ98JQfMSWgJojBH2ZT2eGO7KiDjF475badW9c33CrrW4ybVIyPuHAgMBAAECggEARb6kE5iOiryhvRnQEBErJ7BGBFa2BUFadUNRdUVftSKN/1btZGFs+1MNz9+LAwRAMlX0a2V9f5+vei9uOTBqiRg0WMSOls36umzw0hNXOgJVXh7JWs5D/wzAVzAViakF/5MrK6j7l+wNdl8ALhBDUxiSZq03h3aFCMn8HCpCKIpE+jdsUAD2aSZXt3G+Q1VZqon1bX0a4+wFJ99Ji5bBt9GRRzOKG6Oj7iEBhmfom6wQDjD7AH3qeC5O9TUSD3op3gUc8ONp3vcCCpG0jTiQIsfETxdLmapv/4XhsKvkkaUpXgM0cZaJc0O9Bk+qic7GQOsaQi84+lw89N+wRH9e0QKBgQDF9s4xOVArczFIvl4oTjEWfkDonQu3e6d8Z4JegHD2+lyDv6h7y5kwg6oSjxjtblLhlvt6GeEpSfSVB8dUKiKs4ta/RIk/29cO/gIcLWdnnFb4WQzKIZO6Z6O0t9FiK9kEsCDq6/9wkvOOErxpdgqOEEMLBMFuRju//5DonpIssQKBgQDoeAPfRWCBqDH140G0N82vSY7hGnNUhM0Z9+oaf12hY6JlUBNYR4rKYNOy0z0UIvUyIP1jYWRFtvRNJvt9CDKO2t53gArZ7MIA2+BUxME7IMHeMBTixz3dFuEeTmIXK4Y7Qr7ODLA5l1gjkWoCK/9Obk5kvMdFyxmWAjrwAznZtwKBgAqv4j3CDFPsKhL1Q/wFDJ1cP4DPSZykLkyHAgC8Cl0q8ueh5ySXvzNhSEMsOnpG5G6NShIzZ3ZlKbEJ9HbUt36B2HoG5yntYlTK3a5LvTNYu1E47XnUCjeb9LiC2+ji2Rppr70+9FFNfZyD4mwHFVbKBfSIUzDy1bLtxxLnzJhhAoGBANTlTI6GJ9q2IYMRrBOS44C7eel3YtWthXRZ0gCQUjxCVfA4xG6dnmK3CEmGITK2zR0qj0QbZkxeQCAEKl8YSc0Abqq8DbQEmqtUsn6PbnNrDYEhQY9qbqJymJo7qKOVjanp93oWrrEfhG2Wd6Ijjv3SEWM6a7jkRrtVsYorOijDAoGBALZcLbf+KnounOHXhzDNoZwSm18OPtq/v4CUX7fgVNkfcMVWCZLpX7WnimkBoaFuqs9Zwj80WwdMHprtwf2HOvpTOTxx+0au4bqLR/HB3nP4r1JSnbFgNJ5SlD1hOrZgXkyimScmePNgbhOoIglD86g0bJlMHLdknAVjskGCm+Tt\n"
"-----END PRIVATE KEY-----\n";

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

// Declare global variables for mbedtls contexts
mbedtls_pk_context pk;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

// Initialize mbedtls contexts once at the beginning
void mbedtls_init() {
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
}

// Clean up mbedtls contexts at the end
void mbedtls_cleanup() {
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int rsa_encrypt(const char *plaintext, size_t plaintext_len, unsigned char *encrypted, char *base64_ret_encrypted) { //

    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)public_key_str, strlen(public_key_str) + 1);
    if (ret != 0) {
        printf("Failed to parse public key: -0x%04X\n", -ret);
        return ret;
    }
    printf("Success to parse public key: -0x%04X\n", -ret);

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, plaintext_len, (const unsigned char *)plaintext, encrypted);
    if (ret != 0) {
        printf("Encryption failed: -0x%04X\n", -ret);
    } else {
        printf("Success to encrypt using public key: -0x%04X\n", -ret);

        char encrypted_hex[MBEDTLS_MPI_MAX_SIZE * 2];
        for (size_t i = 0; i < mbedtls_mpi_size(&rsa->N); ++i) {
            snprintf(&encrypted_hex[i * 2], 3, "%02X", encrypted[i]);
        }

        ret = hex_to_base64(encrypted_hex, mbedtls_mpi_size(&rsa->N) * 2, base64_ret_encrypted, MBEDTLS_MPI_MAX_SIZE * 2);
        if (ret != 0) {
            printf("Conversion to Base64 failed: -0x%04X\n", -ret);
            return ret;
        }
    }

    mbedtls_cleanup();

    return ret;
}

int rsa_decrypt(const unsigned char *cyphertext, size_t output_len, unsigned char *output) { 
    int ret = 0;    

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)private_key_str, strlen(private_key_str) + 1, NULL, 0);
    if (ret != 0) {
        printf("Failed to parse private key: -0x%04X\n", -ret);
        return ret;
    }
    printf("Success to parse private key: -0x%04X\n", -ret);

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    ret = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &output_len, cyphertext, output, MBEDTLS_MPI_MAX_SIZE);
    if (ret != 0) {
        printf("Decryption failed: -0x%04X\n", -ret);
    } else {
        printf("Success to decrypt using private key: -0x%04X\n", -ret);
    }

    mbedtls_cleanup();

    return ret;
}

void app_main() {
    mbedtls_init();

    // uint8_t data[64] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    //                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    //                     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    //                     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};

    const char *plaintext = "Hello, World!";

    unsigned char encrypted[MBEDTLS_MPI_MAX_SIZE];
    memset(encrypted, 0, MBEDTLS_MPI_MAX_SIZE);
    
    unsigned char decrypted[MBEDTLS_MPI_MAX_SIZE];
    memset(decrypted, 0, sizeof(decrypted));

    size_t output_len = 0; 

    char base64_encrypted[MBEDTLS_MPI_MAX_SIZE * 2];
    memset(base64_encrypted, 0, MBEDTLS_MPI_MAX_SIZE * 2);

    int ret = rsa_encrypt(plaintext, strlen(plaintext),encrypted, base64_encrypted); //
    if (ret != 0) {
        printf("Encryption failed: -0x%04X\n", -ret);
    }
    else {
        printf("Encoded encrypted data: %s\n", base64_encrypted);
        printf("Encryption success: -0x%04X\n", -ret);
    }

    ret = rsa_decrypt((const unsigned char *)encrypted, output_len, decrypted);
    if (ret != 0) {
        printf("Decryption failed: -0x%04X\n", -ret);
    }
    else {
        printf("Decryption success: -0x%04X\n", -ret);
        printf("Decrypted data: %s\n", decrypted);
    }


}
