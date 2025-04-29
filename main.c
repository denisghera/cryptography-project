#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t *read_file(const char *filename, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(*len + 16);
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

void add_padding(uint8_t **data, size_t *len) {
    size_t pad = 16 - (*len % 16);
    *data = realloc(*data, *len + pad);
    memset(*data + *len, pad, pad);
    *len += pad;
}

int remove_padding(uint8_t *data, size_t *len) {
    uint8_t pad = data[*len - 1];
    if (pad > 16) return -1;
    *len -= pad;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s <encrypt/decrypt> <input> <output> <key>\n", argv[0]);
        return 1;
    }

    // Read input
    size_t len;
    uint8_t *data = read_file(argv[2], &len);
    if (!data) { perror("Read error"); return 1; }

    // Convert key from hex
    uint8_t key[16];
    for (int i = 0; i < 16; i++) sscanf(argv[4] + 2*i, "%2hhx", key+i);

    if (strcmp(argv[1], "encrypt") == 0) {
        // Generate IV (for demo, use zero IV)
        uint8_t iv[16] = {0};
        add_padding(&data, &len);
        uint8_t *ciphertext = malloc(len + 16);
        memcpy(ciphertext, iv, 16);
        aes_cbc_encrypt(data, len, key, iv, ciphertext + 16);
        write_file(argv[3], ciphertext, len + 16);
        free(ciphertext);
    } else {
        // Read IV from first 16 bytes
        if (len < 16) { printf("Invalid file\n"); return 1; }
        uint8_t iv[16];
        memcpy(iv, data, 16);
        size_t ciphertext_len = len - 16;
        uint8_t *plaintext = malloc(ciphertext_len);
        aes_cbc_decrypt(data + 16, ciphertext_len, key, iv, plaintext);
        remove_padding(plaintext, &ciphertext_len);
        write_file(argv[3], plaintext, ciphertext_len);
        free(plaintext);
    }

    free(data);
    return 0;
}