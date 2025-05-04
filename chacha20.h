#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce, 
                     uint32_t counter, uint8_t *data, size_t len);

#endif // CHACHA20_H