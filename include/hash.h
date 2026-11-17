#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Password hashing (EDUCATIONAL ONLY).
 * We use FNV-1a (a simple 64-bit hash) with a random salt and 1000 rounds.
 * Real systems should use bcrypt, scrypt or Argon2 instead: FNV-1a is fast,
 * and a fast hash is easy to brute force.
 */

#define SALT_LEN 16      /* salt stored as 16 hex characters (8 random bytes) */
#define HASH_HEX_LEN 16  /* 64-bit hash stored as 16 hex characters */
#define HASH_ROUNDS 1000 /* repeat the hash to make guessing slower */

/* FNV-1a over len bytes, continuing from the hash value h. */
uint64_t fnv1a64(const void *data, size_t len, uint64_t h);

/* Starting value for fnv1a64. */
uint64_t fnv1a64_start(void);

/* Fills out with SALT_LEN random hex characters (+ '\0'). */
void generate_salt(char out[SALT_LEN + 1]);

/* hash(salt + password), repeated HASH_ROUNDS times, written as hex into out. */
void hash_password(const char *password, const char *salt, char out[HASH_HEX_LEN + 1]);

/* Compares two buffers in a time that does not depend on where they differ
 * (so an attacker cannot learn the hash by timing the comparison). */
int constant_time_equals(const char *a, const char *b, size_t len);

/* Overwrites memory with zeros (used to wipe passwords after use). */
void secure_zero(void *p, size_t n);

#endif
