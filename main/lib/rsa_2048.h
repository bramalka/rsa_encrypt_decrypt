#ifndef RSA_2048_H
#define RSA_2048_H

#include <stddef.h>

void mbedtls_init();
int rsa_encrypt(const char *plaintext, size_t plaintext_len, unsigned char *encrypted, char *base64_ret_encrypted, const char *public_key_str);
int rsa_decrypt(const unsigned char *cyphertext, size_t output_len, unsigned char *output, const char *private_key_str);

#endif /* RSA_2048_H */