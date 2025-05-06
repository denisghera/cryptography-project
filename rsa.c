#include "rsa.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h> 

// Miller-Rabin primality test
static int is_prime(const mpz_t n) {
    return mpz_probab_prime_p(n, 25) > 0;
}

int rsa_genkey(int bits, const char *pubfile, const char *privfile) {
    mpz_t p, q, n, phi, e, d;
    gmp_randstate_t st;
    gmp_randinit_default(st);
    uint32_t seed;
    FILE *urandom = fopen("/dev/urandom", "rb");
    fread(&seed, sizeof(seed), 1, urandom);
    fclose(urandom);
    gmp_randseed_ui(st, seed);

    mpz_inits(p, q, n, phi, e, d, NULL);

    // generate prime p (with explicit primality check)
    do {
        mpz_urandomb(p, st, bits/2);    // random number
        mpz_nextprime(p, p);            // find next prime ≥ p
    } while (!is_prime(p));

    // generate distinct prime q (with explicit check)
    do {
        do {
            mpz_urandomb(q, st, bits/2);
            mpz_nextprime(q, q);
        } while (!is_prime(q));
    } while (mpz_cmp(p, q) == 0);

    // n = p*q
    mpz_mul(n, p, q);
    // phi = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    mpz_set_ui(e, 65537);
    // d = e^{-1} mod phi
    if (mpz_invert(d, e, phi) == 0) {
        fprintf(stderr, "Failed to compute d\n");
        return -1;
    }

    // write public key
    FILE *f = fopen(pubfile, "w");
    if (!f) {
        fprintf(stderr, "Couldn't open %s: %s\n", pubfile, strerror(errno));
        return -1;
    }
    gmp_fprintf(f, "%Zx %Zx", n, e);
    fclose(f);
    // write private key
    f = fopen(privfile, "w");
    gmp_fprintf(f, "%Zx %Zx", n, d);
    fclose(f);

    mpz_clears(p, q, phi, e, d, n, NULL);
    gmp_randclear(st);
    return 0;
}

int rsa_encrypt_file(const char *pubfile, const char *infile, const char *outfile) {
    mpz_t n, e, m, c;
    mpz_inits(n, e, m, c, NULL);
    
    // Read public key
    FILE *f = fopen(pubfile, "r");
    if (!f) {
        fprintf(stderr, "Can't open public key %s: %s\n", pubfile, strerror(errno));
        return -1;
    }
    if (gmp_fscanf(f, "%Zx %Zx", n, e) != 2) {
        fprintf(stderr, "Invalid public key format\n");
        fclose(f);
        return -1;
    }
    fclose(f);

    FILE *in = fopen(infile, "rb");
    if (!in) return -1;
    FILE *out = fopen(outfile, "wb");
    if (!out) { fclose(in); return -1; }

    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8;
    size_t max_pt = k - 11;  // PKCS#1 v1.5 max plaintext size
    
    uint8_t *pt_block = malloc(max_pt);
    uint8_t *padded_block = malloc(k);

    while (1) {
        size_t r = fread(pt_block, 1, max_pt, in);
        if (r == 0) break;

        // Build PKCS#1 v1.5 padded block
        padded_block[0] = 0x00;
        padded_block[1] = 0x02;
        
        // Generate random non-zero padding (length = k - r - 3)
        size_t padding_len = k - r - 3;
        FILE *urandom = fopen("/dev/urandom", "rb");
        fread(padded_block + 2, 1, padding_len, urandom);
        fclose(urandom);

        // Ensure no zero bytes in padding
        for (size_t i = 2; i < 2 + padding_len; i++) {
            while (padded_block[i] == 0) {
                padded_block[i] = (uint8_t)rand() % 255 + 1;
            }
        }

        // Add delimiter and plaintext
        padded_block[2 + padding_len] = 0x00;
        memcpy(padded_block + 3 + padding_len, pt_block, r);

        // Encrypt
        mpz_import(m, k, 1, 1, 0, 0, padded_block);
        mpz_powm(c, m, e, n);

        // Write ciphertext
        uint8_t *cbuf = malloc(k);
        size_t count;
        mpz_export(cbuf, &count, 1, 1, 0, 0, c);
        fwrite(cbuf, 1, k, out);
        free(cbuf);
    }

    free(pt_block);
    free(padded_block);
    fclose(in);
    fclose(out);
    mpz_clears(n, e, m, c, NULL);
    return 0;
}

int rsa_decrypt_file(const char *privfile, const char *infile, const char *outfile) {
    mpz_t n, d, m, c;
    mpz_inits(n, d, m, c, NULL);

    // Read private key
    FILE *f = fopen(privfile, "r");
    if (!f || gmp_fscanf(f, "%Zx %Zx", n, d) != 2) {
        fprintf(stderr, "Key read error\n");
        return -1;
    }
    fclose(f);

    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out) return -1;

    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8;
    uint8_t *buf = malloc(k);
    uint8_t *padded_block = calloc(1, k);

    while (fread(buf, 1, k, in) == k) {
        // Decrypt
        mpz_import(c, k, 1, 1, 0, 0, buf);
        mpz_powm(m, c, d, n);

        // Extract padded block (preserve leading zeros)
        size_t count;
        mpz_export(padded_block + (k - mpz_sizeinbase(m, 256)), &count, 1, 1, 0, 0, m);

        // Validate PKCS#1 padding
        if (padded_block[0] != 0x00 || padded_block[1] != 0x02) {
            fprintf(stderr, "Invalid padding header\n");
            free(padded_block);
            free(buf);
            return -1;
        }

        // Find 0x00 delimiter
        size_t delim = 2;
        while (delim < k && padded_block[delim] != 0x00) delim++;
        
        if (delim >= count - 1) {
            fprintf(stderr, "Invalid padding (no delimiter)\n");
            free(padded_block);
            free(buf);
            return -1;
        }

        // Write plaintext
        size_t pt_len = k - delim - 1;
        fwrite(padded_block + delim + 1, 1, pt_len, out);
        memset(padded_block, 0, k); // Reset buffer
    }

    free(buf);
    free(padded_block);
    fclose(in);
    fclose(out);
    mpz_clears(n, d, m, c, NULL);
    return 0;
}