#include <stdio.h>
#include <string.h>
#include "rsa_2048.h"  

#define RSA_MAX_LEN 1024

const char *public_key_str =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8R5i88R2+WladPnHDA4EY2hxw0jO8OG/GsiH0UvBMzW74XHa2vUVOAmh8inXB85R3DRMPdI7i+k10SdNjBLZ/oieS4pUty9ylKppmJepRrFK7uhoupTfS5Nfp4MZDRpa6LbLwudw2VOMGw9NJiMOVPWklusYUzHxFiMkv/896tZ+bDUWLSYz4A60YDooZkxs2jev7EwxXCGkIVZtgE90wRF0BC8qbLLK/w1oQPdU+RnXjv7Ykfx+3II0Iw62mjHfrsZMo6zo94lKpV8YK8XK9OVpkUjPv49s0PfCUHzEloCaIwR9mU9nhjuyog4xeO+W2nVvXN9wq61uMm1SMj7hwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const char *private_key_str = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzxHmLzxHb5aVp0+ccMDgRjaHHDSM7w4b8ayIfRS8EzNbvhcdra9RU4CaHyKdcHzlHcNEw90juL6TXRJ02MEtn+iJ5LilS3L3KUqmmYl6lGsUru6Gi6lN9Lk1+ngxkNGlrotsvC53DZU4wbD00mIw5U9aSW6xhTMfEWIyS//z3q1n5sNRYtJjPgDrRgOihmTGzaN6/sTDFcIaQhVm2AT3TBEXQELypsssr/DWhA91T5GdeO/tiR/H7cgjQjDraaMd+uxkyjrOj3iUqlXxgrxcr05WmRSM+/j2zQ98JQfMSWgJojBH2ZT2eGO7KiDjF475badW9c33CrrW4ybVIyPuHAgMBAAECggEARb6kE5iOiryhvRnQEBErJ7BGBFa2BUFadUNRdUVftSKN/1btZGFs+1MNz9+LAwRAMlX0a2V9f5+vei9uOTBqiRg0WMSOls36umzw0hNXOgJVXh7JWs5D/wzAVzAViakF/5MrK6j7l+wNdl8ALhBDUxiSZq03h3aFCMn8HCpCKIpE+jdsUAD2aSZXt3G+Q1VZqon1bX0a4+wFJ99Ji5bBt9GRRzOKG6Oj7iEBhmfom6wQDjD7AH3qeC5O9TUSD3op3gUc8ONp3vcCCpG0jTiQIsfETxdLmapv/4XhsKvkkaUpXgM0cZaJc0O9Bk+qic7GQOsaQi84+lw89N+wRH9e0QKBgQDF9s4xOVArczFIvl4oTjEWfkDonQu3e6d8Z4JegHD2+lyDv6h7y5kwg6oSjxjtblLhlvt6GeEpSfSVB8dUKiKs4ta/RIk/29cO/gIcLWdnnFb4WQzKIZO6Z6O0t9FiK9kEsCDq6/9wkvOOErxpdgqOEEMLBMFuRju//5DonpIssQKBgQDoeAPfRWCBqDH140G0N82vSY7hGnNUhM0Z9+oaf12hY6JlUBNYR4rKYNOy0z0UIvUyIP1jYWRFtvRNJvt9CDKO2t53gArZ7MIA2+BUxME7IMHeMBTixz3dFuEeTmIXK4Y7Qr7ODLA5l1gjkWoCK/9Obk5kvMdFyxmWAjrwAznZtwKBgAqv4j3CDFPsKhL1Q/wFDJ1cP4DPSZykLkyHAgC8Cl0q8ueh5ySXvzNhSEMsOnpG5G6NShIzZ3ZlKbEJ9HbUt36B2HoG5yntYlTK3a5LvTNYu1E47XnUCjeb9LiC2+ji2Rppr70+9FFNfZyD4mwHFVbKBfSIUzDy1bLtxxLnzJhhAoGBANTlTI6GJ9q2IYMRrBOS44C7eel3YtWthXRZ0gCQUjxCVfA4xG6dnmK3CEmGITK2zR0qj0QbZkxeQCAEKl8YSc0Abqq8DbQEmqtUsn6PbnNrDYEhQY9qbqJymJo7qKOVjanp93oWrrEfhG2Wd6Ijjv3SEWM6a7jkRrtVsYorOijDAoGBALZcLbf+KnounOHXhzDNoZwSm18OPtq/v4CUX7fgVNkfcMVWCZLpX7WnimkBoaFuqs9Zwj80WwdMHprtwf2HOvpTOTxx+0au4bqLR/HB3nP4r1JSnbFgNJ5SlD1hOrZgXkyimScmePNgbhOoIglD86g0bJlMHLdknAVjskGCm+Tt\n"
"-----END PRIVATE KEY-----\n";

void app_main() {
    mbedtls_init();

    const char *plaintext = "Hello, World!";

    unsigned char encrypted[RSA_MAX_LEN];
    memset(encrypted, 0, RSA_MAX_LEN);
    
    unsigned char decrypted[RSA_MAX_LEN];
    memset(decrypted, 0, sizeof(decrypted));

    size_t output_len = 0; 

    char base64_encrypted[RSA_MAX_LEN * 2];
    memset(base64_encrypted, 0, RSA_MAX_LEN * 2);

    int ret = rsa_encrypt(plaintext, strlen(plaintext),encrypted, base64_encrypted, public_key_str); //
    if (ret != 0) {
        printf("Encryption failed: -0x%04X\n", -ret);
    }
    else {
        printf("Encoded encrypted data: %s\n", base64_encrypted);
        printf("Encryption success: -0x%04X\n", -ret);
    }

    ret = rsa_decrypt((const unsigned char *)encrypted, output_len, decrypted, private_key_str);
    if (ret != 0) {
        printf("Decryption failed: -0x%04X\n", -ret);
    }
    else {
        printf("Decryption success: -0x%04X\n", -ret);
        printf("Decrypted data: %s\n", decrypted);
    }
}
