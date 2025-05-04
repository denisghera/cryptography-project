#include "aes.h"
#include "chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CIPHER_AES 0
#define CIPHER_CHACHA20 1

uint8_t *read_file(const char *filename, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(*len);
    if (!data) { fclose(f); return NULL; }
    fread(data, 1, *len, f);
    fclose(f);
    return data;
}

int write_file(const char *filename, uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);
    return 0;
}

void handle_padding(uint8_t **data, size_t *len, int mode, int cipher) {
    if (cipher == CIPHER_AES) {
        if (mode == 0) {  // Encrypt
            size_t pad = 16 - (*len % 16);
            pad = pad ? pad : 16; // Always add padding (even if aligned)
            *data = realloc(*data, *len + pad);
            memset(*data + *len, pad, pad);
            *len += pad;
        } else {          // Decrypt
            if (*len == 0) return; // Avoid underflow
            uint8_t pad = (*data)[*len - 1];
            // Validate padding (1-16 and all bytes equal to pad)
            int valid = (pad >= 1 && pad <= 16);
            if (valid) {
                for (size_t i = *len - pad; i < *len; i++) {
                    if ((*data)[i] != pad) {
                        valid = 0;
                        break;
                    }
                }
            }
            if (valid) {
                *len -= pad; // Truncate valid padding
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 6) {
        printf("Usage: %s <encrypt/decrypt> <aes|chacha20> <input> <output> <key>\n", argv[0]);
        return 1;
    }

    int cipher = strcmp(argv[2], "aes") == 0 ? CIPHER_AES : CIPHER_CHACHA20;
    size_t key_len = cipher == CIPHER_AES ? 32 : 64;  // Hex characters
    if (strlen(argv[5]) != key_len) {
        printf("Invalid key length for %s (needs %zu hex chars)\n", argv[2], key_len);
        return 1;
    }

    // Read input
    size_t len;
    uint8_t *data = read_file(argv[3], &len);
    if (!data) { perror("Read error"); return 1; }

    // Convert key from hex
    uint8_t key[32];  // Max size for ChaCha20
    for (size_t i = 0; i < key_len/2; i++) {
        sscanf(argv[5] + 2*i, "%2hhx", key+i);
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        if (cipher == CIPHER_AES) {
            // AES-CBC
            uint8_t iv[16] = {0};  // Should be random in real use
            handle_padding(&data, &len, 0, CIPHER_AES);
            uint8_t *ciphertext = malloc(len + 16);
            memcpy(ciphertext, iv, 16);
            aes_cbc_encrypt(data, len, key, iv, ciphertext + 16);
            write_file(argv[4], ciphertext, len + 16);
            free(ciphertext);
        } else {
            // ChaCha20
            uint8_t nonce[12] = {0};  // Should be random in real use
            uint32_t counter = 0;
            uint8_t *ciphertext = malloc(len + 12);
            memcpy(ciphertext, nonce, 12);
            chacha20_encrypt(key, nonce, counter, data, len);
            memcpy(ciphertext + 12, data, len);
            write_file(argv[4], ciphertext, len + 12);
            free(ciphertext);
        }
    } else {
        // Inside the AES decrypt block:
        if (cipher == CIPHER_AES) {
            // AES-CBC
            if (len < 16) { printf("Invalid file\n"); return 1; }
            uint8_t iv[16];
            memcpy(iv, data, 16);
            size_t plaintext_len = len - 16; // Correct initial plaintext length
            uint8_t *plaintext = malloc(plaintext_len);
            aes_cbc_decrypt(data + 16, plaintext_len, key, iv, plaintext);
            handle_padding(&plaintext, &plaintext_len, 1, CIPHER_AES); // Pass correct length
            write_file(argv[4], plaintext, plaintext_len); // Use adjusted length
            free(plaintext);
        } else {
            // ChaCha20
            if (len < 12) { printf("Invalid file\n"); return 1; }
            uint8_t nonce[12];
            memcpy(nonce, data, 12);
            uint32_t counter = 0;
            uint8_t *plaintext = malloc(len - 12);
            memcpy(plaintext, data + 12, len - 12);
            chacha20_encrypt(key, nonce, counter, plaintext, len - 12);
            write_file(argv[4], plaintext, len - 12);
            free(plaintext);
        }
    }

    free(data);
    return 0;
}