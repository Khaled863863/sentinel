#include "auth.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void userdb_init(UserDB *db)
{
    db->users = NULL;
    db->count = 0;
    db->capacity = 0;
}

void userdb_free(UserDB *db)
{
    if (db->users != NULL) {
        secure_zero(db->users, db->capacity * sizeof(User));
    }
    free(db->users);
    userdb_init(db);
}

/* First position whose username is >= name (binary search, O(log n)). */
static size_t lower_bound(const UserDB *db, const char *name)
{
    size_t lo = 0;
    size_t hi = db->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(db->users[mid].username, name) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

long userdb_find(const UserDB *db, const char *username)
{
    size_t i = lower_bound(db, username);
    if (i < db->count && strcmp(db->users[i].username, username) == 0) {
        return (long)i;
    }
    return -1;
}

/* Doubles the array when it is full (amortized O(1) growth). */
static int ensure_capacity(UserDB *db)
{
    if (db->count < db->capacity) {
        return 0;
    }
    size_t new_capacity = db->capacity ? db->capacity * 2 : 8;
    User *bigger = realloc(db->users, new_capacity * sizeof *bigger);
    if (bigger == NULL) {
        return -1;
    }
    db->users = bigger;
    db->capacity = new_capacity;
    return 0;
}

/* Inserts u at its sorted position. O(log n) to find the spot, O(n) to shift. */
static int insert_user(UserDB *db, const User *u)
{
    size_t pos = lower_bound(db, u->username);
    if (pos < db->count && strcmp(db->users[pos].username, u->username) == 0) {
        return -1;
    }
    if (ensure_capacity(db) != 0) {
        return -2;
    }
    memmove(&db->users[pos + 1], &db->users[pos], (db->count - pos) * sizeof(User));
    db->users[pos] = *u;
    db->count++;
    return 0;
}

int userdb_add(UserDB *db, const char *username, const char *password, Role role)
{
    User u;
    memset(&u, 0, sizeof u);
    snprintf(u.username, sizeof u.username, "%s", username);
    generate_salt(u.salt);
    hash_password(password, u.salt, u.hash);
    u.role = role;
    return insert_user(db, &u);
}

int userdb_remove(UserDB *db, const char *username)
{
    long i = userdb_find(db, username);
    if (i < 0) {
        return -1;
    }
    size_t idx = (size_t)i;
    memmove(&db->users[idx], &db->users[idx + 1], (db->count - idx - 1) * sizeof(User));
    db->count--;
    secure_zero(&db->users[db->count], sizeof(User));
    return 0;
}

int userdb_load(UserDB *db, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (errno == ENOENT) {
            return 0; /* first run: no users yet */
        }
        perror(path);
        return -1;
    }

    char line[256];
    int line_no = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        line_no++;
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        char name[64], salt[64], hash[64];
        int role, failed;
        long long locked;
        if (sscanf(line, "%63s %63s %63s %d %d %lld", name, salt, hash, &role, &failed, &locked) != 6
            || strlen(name) > MAX_USERNAME || strlen(salt) != SALT_LEN
            || strlen(hash) != HASH_HEX_LEN || role < 0 || role >= ROLE_COUNT
            || failed < 0 || locked < 0) {
            fprintf(stderr, "Warning: skipping a damaged line (%d) in %s\n", line_no, path);
            continue;
        }

        User u;
        memset(&u, 0, sizeof u);
        /* The lengths were checked above, so these copies always fit. */
        memcpy(u.username, name, strlen(name) + 1);
        memcpy(u.salt, salt, SALT_LEN + 1);
        memcpy(u.hash, hash, HASH_HEX_LEN + 1);
        u.role = (Role)role;
        u.failed_attempts = failed;
        u.locked_until = (time_t)locked;

        if (insert_user(db, &u) == -2) {
            fclose(f);
            return -1;
        }
    }

    int had_error = ferror(f);
    fclose(f);
    return had_error ? -1 : 0;
}

int userdb_save(const UserDB *db, const char *path)
{
    /* Write to a temporary file first, then rename it over the old one.
     * This way a crash in the middle never leaves a half-written database. */
    char tmp_path[512];
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path) >= (int)sizeof tmp_path) {
        return -1;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600); /* owner-only permissions */
    if (fd < 0) {
        perror(tmp_path);
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (f == NULL) {
        perror(tmp_path);
        close(fd);
        return -1;
    }

    fprintf(f, "# username salt hash role failed_attempts locked_until\n");
    for (size_t i = 0; i < db->count; i++) {
        const User *u = &db->users[i];
        fprintf(f, "%s %s %s %d %d %lld\n", u->username, u->salt, u->hash,
                (int)u->role, u->failed_attempts, (long long)u->locked_until);
    }

    if (fclose(f) != 0) {
        perror(tmp_path);
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

AuthResult auth_login(UserDB *db, const char *username, const char *password,
                      time_t now, long *out_index)
{
    long i = userdb_find(db, username);
    if (out_index != NULL) {
        *out_index = i;
    }

    if (i < 0) {
        /* Hash anyway, so a missing user takes as long as a wrong password
         * (otherwise timing would tell an attacker which usernames exist). */
        char dummy[HASH_HEX_LEN + 1];
        hash_password(password, "0000000000000000", dummy);
        return AUTH_NO_SUCH_USER;
    }

    User *u = &db->users[i];
    if (u->locked_until > now) {
        return AUTH_LOCKED;
    }

    char hash[HASH_HEX_LEN + 1];
    hash_password(password, u->salt, hash);

    if (constant_time_equals(hash, u->hash, HASH_HEX_LEN)) {
        u->failed_attempts = 0;
        u->locked_until = 0;
        return AUTH_OK;
    }

    u->failed_attempts++;
    if (u->failed_attempts >= MAX_FAILED_ATTEMPTS) {
        u->failed_attempts = 0;
        u->locked_until = now + LOCKOUT_SECONDS;
        return AUTH_NOW_LOCKED;
    }
    return AUTH_WRONG_PASSWORD;
}

int auth_change_password(UserDB *db, long index, const char *new_password)
{
    if (index < 0 || (size_t)index >= db->count) {
        return -1;
    }
    User *u = &db->users[index];
    generate_salt(u->salt);
    hash_password(new_password, u->salt, u->hash);
    u->failed_attempts = 0;
    return 0;
}

long auth_lock_remaining(const User *u, time_t now)
{
    if (u->locked_until > now) {
        return (long)(u->locked_until - now);
    }
    return 0;
}
