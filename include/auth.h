#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <time.h>

#include "access.h"
#include "hash.h"

/*
 * User accounts and login.
 * Users are kept in a dynamic array sorted by username, so we can find
 * a user with binary search in O(log n).
 */

#define MAX_USERNAME 16
#define MAX_FAILED_ATTEMPTS 3 /* wrong passwords before the account locks */
#define LOCKOUT_SECONDS 30    /* how long a locked account stays locked */

typedef struct {
    char username[MAX_USERNAME + 1];
    char salt[SALT_LEN + 1];
    char hash[HASH_HEX_LEN + 1]; /* we never store the password itself */
    Role role;
    int failed_attempts;
    time_t locked_until; /* 0 when the account is not locked */
} User;

typedef struct {
    User *users;     /* sorted by username */
    size_t count;
    size_t capacity;
} UserDB;

typedef enum {
    AUTH_OK,
    AUTH_NO_SUCH_USER,
    AUTH_WRONG_PASSWORD,
    AUTH_LOCKED,     /* the account was already locked */
    AUTH_NOW_LOCKED  /* this wrong password locked the account */
} AuthResult;

void userdb_init(UserDB *db);
void userdb_free(UserDB *db);

/* Loads users from a file. A missing file is fine (empty database).
 * Returns 0 on success, -1 on error. */
int userdb_load(UserDB *db, const char *path);

/* Saves users to a file (readable only by the owner). Returns 0 or -1. */
int userdb_save(const UserDB *db, const char *path);

/* Binary search. Returns the index of the user, or -1 if not found. */
long userdb_find(const UserDB *db, const char *username);

/* Adds a user with a new random salt. Returns 0, -1 if the name is taken, -2 if out of memory. */
int userdb_add(UserDB *db, const char *username, const char *password, Role role);

/* Removes a user. Returns 0, or -1 if not found. */
int userdb_remove(UserDB *db, const char *username);

/* Checks a username and password and updates the lockout counters.
 * out_index receives the user's index (or -1). */
AuthResult auth_login(UserDB *db, const char *username, const char *password,
                      time_t now, long *out_index);

/* Sets a new password (with a new salt). Returns 0, or -1 on bad index. */
int auth_change_password(UserDB *db, long index, const char *new_password);

/* Seconds left before a locked account opens again (0 if not locked). */
long auth_lock_remaining(const User *u, time_t now);

#endif
