#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

void aes_encrypt_block(uint8_t *block, const uint8_t *expanded_key);
void aes_decrypt_block(uint8_t *block, const uint8_t *expanded_key);
void key_expansion(const uint8_t *key, uint8_t *expanded_key);

void aes_cbc_encrypt(uint8_t *plaintext, size_t len, const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext);
void aes_cbc_decrypt(uint8_t *ciphertext, size_t len, const uint8_t *key, const uint8_t *iv, uint8_t *plaintext);

#endif // AES_H