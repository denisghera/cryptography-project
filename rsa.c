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

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        return -1;
    }

    while (1) {
        size_t r = fread(pt_block, 1, max_pt, in);
        if (r == 0) break;

        // PKCS#1 v1.5 padding
        padded_block[0] = 0x00;
        padded_block[1] = 0x02;
        size_t padding_len = k - r - 3;
        size_t filled = 0;
        while (filled < padding_len) {
            uint8_t b;
            if (fread(&b, 1, 1, urandom) != 1) {
                fprintf(stderr, "Failed to read from urandom\n");
                return -1;
            }
            if (b != 0x00) {
                padded_block[2 + filled] = b;
                filled++;
            }
        }

        padded_block[2 + padding_len] = 0x00;
        memcpy(padded_block + 3 + padding_len, pt_block, r);

        // Encrypt
        mpz_import(m, k, 1, 1, 1, 0, padded_block);  // big-endian
        mpz_powm(c, m, e, n);

        // Export ciphertext
        uint8_t *cbuf = calloc(1, k);
        size_t count;
        mpz_export(cbuf, &count, 1, 1, 1, 0, c);  // big-endian

        // Ensure we write exactly k bytes (pad with leading 0s if needed)
        if (count < k) {
            memmove(cbuf + (k - count), cbuf, count);
            memset(cbuf, 0, k - count);
        }

        fwrite(cbuf, 1, k, out);
        free(cbuf);
    }

    fclose(urandom);
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
    uint8_t *tmp = malloc(k); // Temporary buffer for mpz_export

    while (fread(buf, 1, k, in) == k) {
        // Decrypt
        mpz_import(c, k, 1, 1, 0, 0, buf);
        mpz_powm(m, c, d, n);

        // Extract padded block using temporary buffer to get accurate byte count
        size_t count;
        mpz_export(tmp, &count, 1, 1, 0, 0, m);
        memset(padded_block, 0, k); // Reset to zeros
        if (count > k) {
            fprintf(stderr, "Decrypted data larger than modulus size\n");
            free(tmp);
            free(padded_block);
            free(buf);
            return -1;
        }
        memcpy(padded_block + (k - count), tmp, count);

        // Validate PKCS#1 padding
        if (padded_block[0] != 0x00 || padded_block[1] != 0x02) {
            fprintf(stderr, "Invalid padding header\n");
            free(tmp);
            free(padded_block);
            free(buf);
            return -1;
        }

        // Find 0x00 delimiter
        size_t delim = 2;
        while (delim < k && padded_block[delim] != 0x00) delim++;
        
        if (delim >= k - 1) {
            fprintf(stderr, "Invalid padding (no delimiter)\n");
            free(tmp);
            free(padded_block);
            free(buf);
            return -1;
        }

        // Write plaintext
        size_t pt_len = k - delim - 1;
        fwrite(padded_block + delim + 1, 1, pt_len, out);
    }

    free(tmp);
    free(buf);
    free(padded_block);
    fclose(in);
    fclose(out);
    mpz_clears(n, d, m, c, NULL);
    return 0;
}