#include "chacha20.h"
#include <string.h>

#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static void chacha20_block(uint32_t *state, uint8_t *key_stream) {
    uint32_t working_state[16];
    memcpy(working_state, state, 64);
    
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        
        // Diagonal rounds
        quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }

    for (int i = 0; i < 16; i++) {
        working_state[i] += state[i];
    }

    // Serialize each 32-bit word to key_stream in little-endian
    for (int i = 0; i < 16; i++) {
        key_stream[4*i + 0] = (uint8_t)(working_state[i] >> 0);
        key_stream[4*i + 1] = (uint8_t)(working_state[i] >> 8);
        key_stream[4*i + 2] = (uint8_t)(working_state[i] >> 16);
        key_stream[4*i + 3] = (uint8_t)(working_state[i] >> 24);
    }
}

void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce, 
                     uint32_t counter, uint8_t *data, size_t len) {
    uint32_t state[16] = {
        // Constants
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        // Key (little-endian conversion)
        (uint32_t)key[0]   | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24),
        (uint32_t)key[4]   | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24),
        (uint32_t)key[8]   | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24),
        (uint32_t)key[12]  | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24),
        (uint32_t)key[16]  | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24),
        (uint32_t)key[20]  | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24),
        (uint32_t)key[24]  | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24),
        (uint32_t)key[28]  | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24),
        // Counter and nonce (little-endian)
        counter,
        (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24),
        (uint32_t)nonce[4] | ((uint32_t)nonce[5] << 8) | ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24),
        (uint32_t)nonce[8] | ((uint32_t)nonce[9] << 8) | ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24)
    };

    // Rest of the function remains unchanged...
    uint8_t key_stream[64];
    size_t pos = 0;
    
    while (len > 0) {
        chacha20_block(state, key_stream);
        state[12]++;  // Increment counter
        
        size_t block_len = len < 64 ? len : 64;
        for (size_t i = 0; i < block_len; i++) {
            data[pos + i] ^= key_stream[i];
        }
        
        pos += block_len;
        len -= block_len;
    }
}