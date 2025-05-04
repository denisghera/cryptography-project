#ifndef RSA_H
#define RSA_H

#include <stddef.h>

int rsa_genkey(int bits, const char *pubfile, const char *privfile);
int rsa_encrypt_file(const char *pubfile, const char *infile, const char *outfile);
int rsa_decrypt_file(const char *privfile, const char *infile, const char *outfile);

#endif // RSA_H