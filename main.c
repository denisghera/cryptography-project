#include "aes.h"
#include "chacha20.h"
#include "rsa.h"
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <menu.h>
#include <form.h>

#define CIPHER_AES 0
#define CIPHER_CHACHA20 1

// NCurses color pairs
enum { DEFAULT_PAIR = 1, TITLE_PAIR, ERROR_PAIR, HIGHLIGHT_PAIR };

WINDOW *main_win;

uint8_t* read_file(const char *filename, size_t *len) {
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

void show_message(const char *msg, int is_error) {
    WINDOW *msg_win = newwin(3, COLS-4, LINES-4, 2);
    wbkgd(msg_win, COLOR_PAIR(is_error ? ERROR_PAIR : HIGHLIGHT_PAIR));
    box(msg_win, 0, 0);
    mvwprintw(msg_win, 1, 2, "%s", msg);
    wrefresh(msg_win);
    napms(2000);
    delwin(msg_win);
    touchwin(stdscr);
    refresh();
}

void init_ncurses() {
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    init_pair(DEFAULT_PAIR, COLOR_WHITE, COLOR_BLUE);
    init_pair(TITLE_PAIR, COLOR_YELLOW, COLOR_BLUE);
    init_pair(ERROR_PAIR, COLOR_WHITE, COLOR_RED);
    init_pair(HIGHLIGHT_PAIR, COLOR_BLACK, COLOR_GREEN);

    main_win = newwin(LINES, COLS, 0, 0);
    wbkgd(main_win, COLOR_PAIR(DEFAULT_PAIR));
}

void handle_padding(uint8_t **data, size_t *len, int mode, int cipher) {
    if (cipher == CIPHER_AES) {
        if (mode == 0) {
            size_t pad = 16 - (*len % 16);
            pad = pad ? pad : 16;
            *data = realloc(*data, *len + pad);
            memset(*data + *len, pad, pad);
            *len += pad;
        } else {
            if (*len == 0) return;
            uint8_t pad = (*data)[*len - 1];
            int valid = (pad >= 1 && pad <= 16);
            if (valid) {
                for (size_t i = *len - pad; i < *len; i++) {
                    if ((*data)[i] != pad) valid = 0;
                }
            }
            if (valid) *len -= pad;
        }
    }
}

void rsa_generate_keys() {
    if (rsa_genkey(2048, "public.key", "private.key")) {
        show_message("RSA key generation failed!", 1);
    } else {
        show_message("RSA keys saved as public.key/private.key", 0);
    }
}

void rsa_process_file(int encrypt) {
    const char *input_file =  encrypt ? "message.txt" : "encrypted_rsa.bin";
    const char *output_file = encrypt ? "encrypted_rsa.bin" : "decrypted_rsa.txt";
    const char *key_file = encrypt ? "public.key" : "private.key";

    FILE *k = fopen(key_file, "rb");
    if (!k) { show_message(encrypt ? "Missing public.key!" : "Missing private.key!", 1); return; }
    fclose(k);

    FILE *f = fopen(input_file, "rb");
    if (!f) { show_message(encrypt ? "Input file message.txt not found!" : "Input file encrypted_rsa.bin not found!", 1); return; }
    fclose(f);

    int result = encrypt ?
        rsa_encrypt_file(key_file, input_file, output_file) :
        rsa_decrypt_file(key_file, input_file, output_file);

    show_message(result ? "RSA operation failed!" : "RSA operation completed!", result);
}

void aes_encrypt() {
    size_t key_len;
    uint8_t *key = read_file("aes.key", &key_len);
    if (!key) {
        show_message("Failed to read AES key file (aes.key)", 1);
        return;
    }
    if (key_len != 16) {
        show_message("AES key must be 16 bytes", 1);
        free(key);
        return;
    }
    uint8_t iv[16];
    FILE *urandom = fopen("/dev/urandom", "rb");
    fread(iv, 1, 16, urandom);
    fclose(urandom);
    size_t len;
    uint8_t *data = read_file("message.txt", &len);
    if (!data) { show_message("Failed to read message.txt", 1); return; }
    handle_padding(&data, &len, 0, CIPHER_AES);
    uint8_t *ciphertext = malloc(len + 16);
    memcpy(ciphertext, iv, 16);
    aes_cbc_encrypt(data, len, key, iv, ciphertext + 16);
    write_file("encrypted_aes.bin", ciphertext, len + 16);
    free(data); free(ciphertext);
    show_message("AES encryption done!", 0);
}

void aes_decrypt() {
    size_t key_len;
    uint8_t *key = read_file("aes.key", &key_len);
    if (!key) {
        show_message("Failed to read AES key file (aes.key)", 1);
        return;
    }
    if (key_len != 16) {
        show_message("AES key must be 16 bytes", 1);
        free(key);
        return;
    }
    size_t len;
    uint8_t *data = read_file("encrypted_aes.bin", &len);
    if (!data || len < 16) { show_message("Invalid AES input file", 1); return; }
    uint8_t iv[16];
    memcpy(iv, data, 16);
    size_t pt_len = len - 16;
    uint8_t *plaintext = malloc(pt_len);
    aes_cbc_decrypt(data + 16, pt_len, key, iv, plaintext);
    handle_padding(&plaintext, &pt_len, 1, CIPHER_AES);
    write_file("decrypted_aes.txt", plaintext, pt_len);
    free(data); free(plaintext);
    show_message("AES decryption done!", 0);
}

void chacha_encrypt() {
    size_t key_len;
    uint8_t *key = read_file("chacha20.key", &key_len);
    if (!key) {
        show_message("Failed to read ChaCha20 key file (chacha20.key)", 1);
        return;
    }
    if (key_len != 32) {
        show_message("ChaCha20 key must be 32 bytes", 1);
        free(key);
        return;
    }
    uint8_t nonce[12];
    FILE *urandom = fopen("/dev/urandom", "rb");
    fread(nonce, 1, 12, urandom);
    fclose(urandom);
    uint32_t counter = 0;
    size_t len;
    uint8_t *data = read_file("message.txt", &len);
    if (!data) { show_message("Failed to read message.txt", 1); return; }
    uint8_t *ciphertext = malloc(len + 12);
    memcpy(ciphertext, nonce, 12);
    chacha20_encrypt(key, nonce, counter, data, len);
    memcpy(ciphertext + 12, data, len);
    write_file("encrypted_cha.bin", ciphertext, len + 12);
    free(data); free(ciphertext);
    show_message("ChaCha20 encryption done!", 0);
}

void chacha_decrypt() {
    size_t key_len;
    uint8_t *key = read_file("chacha20.key", &key_len);
    if (!key) {
        show_message("Failed to read ChaCha20 key file (chacha20.key)", 1);
        return;
    }
    if (key_len != 32) {
        show_message("ChaCha20 key must be 32 bytes", 1);
        free(key);
        return;
    }
    uint32_t counter = 0;
    size_t len;
    uint8_t *data = read_file("encrypted_cha.bin", &len);
    if (!data || len < 12) { show_message("Invalid ChaCha20 input file", 1); return; }
    uint8_t nonce[12];
    memcpy(nonce, data, 12);
    size_t pt_len = len - 12;
    uint8_t *plaintext = malloc(pt_len);
    memcpy(plaintext, data + 12, pt_len);
    chacha20_encrypt(key, nonce, counter, plaintext, pt_len);
    write_file("decrypted_cha.txt", plaintext, pt_len);
    free(data); free(plaintext);
    show_message("ChaCha20 decryption done!", 0);
}

void main_menu() {
    int highlight = 0;
    const char *choices[] = {
        "1. RSA Key Generation",
        "2. RSA Encryption",
        "3. RSA Decryption",
        "4. AES Encryption",
        "5. AES Decryption",
        "6. ChaCha20 Encryption",
        "7. ChaCha20 Decryption",
        "8. Exit"
    };
    int n_choices = sizeof(choices) / sizeof(char *);

    while (1) {
        werase(main_win);
        box(main_win, 0, 0);
        mvwprintw(main_win, 1, 2, "Crypto Toolkit - NCurses");

        for (int i = 0; i < n_choices; ++i) {
            if (i == highlight) wattron(main_win, COLOR_PAIR(HIGHLIGHT_PAIR));
            mvwprintw(main_win, i + 3, 4, "%s", choices[i]);
            wattroff(main_win, COLOR_PAIR(HIGHLIGHT_PAIR));
        }

        wrefresh(main_win);
        int ch = getch();

        switch (ch) {
            case KEY_UP:
                if (highlight > 0) --highlight;
                break;
            case KEY_DOWN:
                if (highlight < n_choices - 1) ++highlight;
                break;
            case 10:
                switch (highlight) {
                    case 0: rsa_generate_keys(); break;
                    case 1: rsa_process_file(1); break;
                    case 2: rsa_process_file(0); break;
                    case 3: aes_encrypt(); break;
                    case 4: aes_decrypt(); break;
                    case 5: chacha_encrypt(); break;
                    case 6: chacha_decrypt(); break;
                    case 7: return;
                }
                break;
            case 'q': return;
        }
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    init_ncurses();
    main_menu();
    return 0;
}
