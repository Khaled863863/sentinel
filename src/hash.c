#include "hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

uint64_t fnv1a64_start(void)
{
    return FNV_OFFSET_BASIS;
}

uint64_t fnv1a64(const void *data, size_t len, uint64_t h)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= FNV_PRIME;
    }
    return h;
}

void generate_salt(char out[SALT_LEN + 1])
{
    unsigned char bytes[SALT_LEN / 2];
    size_t got = 0;

    FILE *f = fopen("/dev/urandom", "rb");
    if (f != NULL) {
        got = fread(bytes, 1, sizeof bytes, f);
        fclose(f);
    }
    if (got != sizeof bytes) {
        /* Fallback if /dev/urandom is missing: weaker, but still different per user. */
        unsigned seed = (unsigned)time(NULL) ^ (unsigned)getpid() ^ (unsigned)clock();
        for (size_t i = 0; i < sizeof bytes; i++) {
            seed = seed * 1103515245u + 12345u;
            bytes[i] = (unsigned char)(seed >> 16);
        }
    }
    for (size_t i = 0; i < sizeof bytes; i++) {
        snprintf(out + 2 * i, 3, "%02x", bytes[i]);
    }
    out[SALT_LEN] = '\0';
}

void hash_password(const char *password, const char *salt, char out[HASH_HEX_LEN + 1])
{
    size_t salt_len = strlen(salt);
    uint64_t h = fnv1a64_start();
    h = fnv1a64(salt, salt_len, h);
    h = fnv1a64(password, strlen(password), h);

    for (int round = 0; round < HASH_ROUNDS; round++) {
        unsigned char b[8];
        for (int k = 0; k < 8; k++) {
            b[k] = (unsigned char)(h >> (8 * k));
        }
        h = fnv1a64(b, sizeof b, fnv1a64_start());
        h = fnv1a64(salt, salt_len, h);
    }
    snprintf(out, HASH_HEX_LEN + 1, "%016llx", (unsigned long long)h);
}

int constant_time_equals(const char *a, const char *b, size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--) {
        *v++ = 0;
    }
}
