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
    gmp_randseed_ui(st, (unsigned long)time(NULL));

    mpz_inits(p, q, n, phi, e, d, NULL);
    // generate two distinct primes p, q
    do { mpz_urandomb(p, st, bits/2); mpz_nextprime(p, p); } while(0);
    do { mpz_urandomb(q, st, bits/2); mpz_nextprime(q, q); } while(mpz_cmp(p,q)==0);

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
    if (!in) {
        fprintf(stderr, "Can't open input %s: %s\n", infile, strerror(errno));
        return -1;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, "Can't create output %s: %s\n", outfile, strerror(errno));
        fclose(in);
        return -1;
    }

    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8;
    size_t bs = k - 11;  // Leave space for PKCS#1 v1.5 padding (even if not implemented)
    uint8_t *buf = malloc(bs);
    if (!buf) {
        fprintf(stderr, "Memory error\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    size_t r;
    while ((r = fread(buf, 1, bs, in)) > 0) {
        mpz_import(m, r, 1, 1, 0, 0, buf);
        mpz_powm(c, m, e, n);
        
        uint8_t *cbuf = malloc(k);
        if (!cbuf) {
            fprintf(stderr, "Memory error\n");
            break;
        }
        size_t count;
        mpz_export(cbuf, &count, 1, 1, 0, 0, c);
        fwrite(cbuf, 1, k, out);
        free(cbuf);
    }

    free(buf);
    fclose(in);
    fclose(out);
    mpz_clears(n, e, m, c, NULL);
    return 0;
}

int rsa_decrypt_file(const char *privfile, const char *infile, const char *outfile) {
    mpz_t n, d, m, c;
    mpz_inits(n, d, m, c, NULL);

    FILE *f = fopen(privfile, "r");
    if (!f) {
        fprintf(stderr, "Can't open private key %s: %s\n", privfile, strerror(errno));
        return -1;
    }
    if (gmp_fscanf(f, "%Zx %Zx", n, d) != 2) {
        fprintf(stderr, "Invalid private key format\n");
        fclose(f);
        return -1;
    }
    fclose(f);

    FILE *in = fopen(infile, "rb");
    if (!in) {
        fprintf(stderr, "Can't open input %s: %s\n", infile, strerror(errno));
        return -1;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, "Can't create output %s: %s\n", outfile, strerror(errno));
        fclose(in);
        return -1;
    }

    size_t k = (mpz_sizeinbase(n, 2) + 7) / 8;
    uint8_t *buf = malloc(k);
    if (!buf) {
        fprintf(stderr, "Memory error\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    size_t r;
    while ((r = fread(buf, 1, k, in)) > 0) {
        mpz_import(c, r, 1, 1, 0, 0, buf);
        mpz_powm(m, c, d, n);
        
        uint8_t *mbuf = malloc(k);
        if (!mbuf) {
            fprintf(stderr, "Memory error\n");
            break;
        }
        size_t count;
        mpz_export(mbuf, &count, 1, 1, 0, 0, m);
        fwrite(mbuf, 1, count, out);
        free(mbuf);
    }

    free(buf);
    fclose(in);
    fclose(out);
    mpz_clears(n, d, m, c, NULL);
    return 0;
}