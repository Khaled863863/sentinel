/*
 * Unit tests for Sentinel. Run with: make test
 * Each CHECK prints a line; the program exits with 1 if any check fails.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "access.h"
#include "attacker.h"
#include "auth.h"
#include "hash.h"
#include "ids.h"
#include "input.h"
#include "simulation.h"

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, name)                                    \
    do {                                                     \
        if (cond) {                                          \
            g_passed++;                                      \
            printf("  [PASS] %s\n", name);                   \
        } else {                                             \
            g_failed++;                                      \
            printf("  [FAIL] %s (line %d)\n", name, __LINE__); \
        }                                                    \
    } while (0)

static void test_hash(void)
{
    char h1[HASH_HEX_LEN + 1], h2[HASH_HEX_LEN + 1], h3[HASH_HEX_LEN + 1];
    char salt1[SALT_LEN + 1], salt2[SALT_LEN + 1];

    printf("Hashing\n");
    generate_salt(salt1);
    generate_salt(salt2);
    CHECK(strlen(salt1) == SALT_LEN, "salt has 16 hex characters");
    CHECK(strcmp(salt1, salt2) != 0, "two salts are different");

    hash_password("secret123", salt1, h1);
    hash_password("secret123", salt1, h2);
    hash_password("secret123", salt2, h3);
    CHECK(strcmp(h1, h2) == 0, "same password + same salt = same hash");
    CHECK(strcmp(h1, h3) != 0, "same password + different salt = different hash");
    CHECK(constant_time_equals("abcdef", "abcdef", 6), "constant_time_equals: equal");
    CHECK(!constant_time_equals("abcdef", "abcdeX", 6), "constant_time_equals: different");
}

static void test_input_rules(void)
{
    printf("Input validation\n");
    CHECK(is_valid_username("khaled_r"), "valid username");
    CHECK(!is_valid_username("ab"), "username too short");
    CHECK(!is_valid_username("bad name"), "username with a space");
    CHECK(!is_valid_username("x';DROP"), "username with symbols");
    CHECK(is_valid_password("Str0ng!pw"), "valid password");
    CHECK(!is_valid_password("12345"), "password too short");
    CHECK(!is_valid_password("has space"), "password with a space");
}

static void test_userdb(void)
{
    UserDB db;
    char path[] = "build/test_users.db";
    time_t now = 1000;
    long idx;

    printf("User database and login\n");
    userdb_init(&db);
    CHECK(userdb_add(&db, "rawad", "password1", ROLE_USER) == 0, "add rawad");
    CHECK(userdb_add(&db, "khaled", "password2", ROLE_ADMIN) == 0, "add khaled");
    CHECK(userdb_add(&db, "alice", "password3", ROLE_USER) == 0, "add alice");
    CHECK(userdb_add(&db, "rawad", "other", ROLE_USER) == -1, "duplicate username rejected");
    CHECK(strcmp(db.users[0].username, "alice") == 0 && strcmp(db.users[2].username, "rawad") == 0,
          "users stay sorted");
    CHECK(userdb_find(&db, "khaled") == 1, "binary search finds khaled");
    CHECK(userdb_find(&db, "nobody") == -1, "binary search: missing user");

    CHECK(auth_login(&db, "khaled", "password2", now, &idx) == AUTH_OK, "correct password");
    CHECK(auth_login(&db, "khaled", "wrong", now, &idx) == AUTH_WRONG_PASSWORD, "wrong password 1");
    CHECK(auth_login(&db, "khaled", "wrong", now, &idx) == AUTH_WRONG_PASSWORD, "wrong password 2");
    CHECK(auth_login(&db, "khaled", "wrong", now, &idx) == AUTH_NOW_LOCKED, "3rd wrong password locks");
    CHECK(auth_login(&db, "khaled", "password2", now + 5, &idx) == AUTH_LOCKED,
          "locked even with the right password");
    CHECK(auth_login(&db, "khaled", "password2", now + LOCKOUT_SECONDS + 1, &idx) == AUTH_OK,
          "unlocked after the lockout time");
    CHECK(auth_login(&db, "ghost", "x", now, &idx) == AUTH_NO_SUCH_USER && idx == -1, "unknown user");

    CHECK(userdb_save(&db, path) == 0, "save to file");
    UserDB copy;
    userdb_init(&copy);
    CHECK(userdb_load(&copy, path) == 0 && copy.count == 3, "load from file");
    CHECK(auth_login(&copy, "alice", "password3", now, &idx) == AUTH_OK, "login works after reload");

    CHECK(userdb_remove(&db, "alice") == 0 && db.count == 2, "remove a user");
    CHECK(userdb_find(&db, "alice") == -1, "removed user is gone");

    userdb_free(&db);
    userdb_free(&copy);
    remove(path);
}

static void test_access(void)
{
    printf("Access control\n");
    CHECK(access_allowed(ROLE_ADMIN, RES_MANAGE_USERS), "admin can manage users");
    CHECK(!access_allowed(ROLE_USER, RES_MANAGE_USERS), "user cannot manage users");
    CHECK(!access_allowed(ROLE_USER, RES_READ_LOG), "user cannot read the log");
    CHECK(access_allowed(ROLE_GUEST, RES_VIEW_PROFILE), "guest can view profile");
    CHECK(!access_allowed(ROLE_GUEST, RES_CHANGE_PASSWORD), "guest cannot change password");
    CHECK(!access_allowed((Role)7, RES_VIEW_PROFILE), "unknown role is denied");
}

static void test_window_and_kmp(void)
{
    TimeWindow w;
    int fail[32];

    printf("Sliding window and KMP\n");
    window_init(&w);
    window_add(&w, 1, 10);
    window_add(&w, 2, 10);
    CHECK(window_add(&w, 5, 10) == 3, "3 events inside the window");
    CHECK(window_add(&w, 12, 10) == 2, "old events leave the window");

    const char *p = "abab";
    kmp_build(p, 4, fail);
    CHECK(fail[0] == 0 && fail[1] == 0 && fail[2] == 1 && fail[3] == 2, "KMP failure table");
    CHECK(kmp_find("xxababyy", 8, p, 4, fail) == 2, "KMP finds the pattern");
    CHECK(kmp_find("xxabayy", 7, p, 4, fail) == -1, "KMP: pattern not present");

    CHECK(signature_match("id=1' OR '1'='1", NULL), "signature: SQL injection");
    CHECK(signature_match("q=1 UNION SELECT pw", NULL), "signature: UNION SELECT (any case)");
    CHECK(signature_match("file=../../etc/passwd", NULL), "signature: path traversal");
    CHECK(!signature_match("GET /home", NULL), "normal request has no signature");
}

static void test_detector(void)
{
    static Detector d;
    Event e;

    printf("Intrusion detector\n");
    detector_init(&d);

    Verdict v = V_ALLOW;
    for (int i = 0; i < BRUTE_LIMIT; i++) {
        event_make(&e, 10 + i, "1.2.3.4", "admin", EV_LOGIN_FAIL, "login");
        v = detector_process(&d, &e);
    }
    CHECK(v == V_BRUTE_FORCE, "brute force caught at the limit");
    event_make(&e, 20, "1.2.3.4", "admin", EV_REQUEST, "GET /");
    CHECK(detector_process(&d, &e) == V_BLOCKED, "attacker is blocked afterwards");
    CHECK(detector_blocked_for(&d, "1.2.3.4", 20) > 0, "blocked_for reports time left");
    event_make(&e, 20 + BLOCK_TICKS, "1.2.3.4", "admin", EV_REQUEST, "GET /");
    CHECK(detector_process(&d, &e) == V_ALLOW, "block ends after BLOCK_TICKS");

    detector_init(&d);
    v = V_ALLOW;
    for (int i = 0; i < FLOOD_LIMIT; i++) {
        event_make(&e, 50, "5.5.5.5", "-", EV_REQUEST, "GET /");
        v = detector_process(&d, &e);
    }
    CHECK(v == V_FLOOD, "flood caught");

    detector_init(&d);
    event_make(&e, 1, "6.6.6.6", "-", EV_REQUEST, "q=1 UNION SELECT x");
    CHECK(detector_process(&d, &e) == V_SIGNATURE, "injection caught by signature");

    detector_init(&d);
    event_make(&e, 1, "7.7.7.7", "-", EV_REQUEST, "GET /home");
    CHECK(detector_process(&d, &e) == V_ALLOW, "normal request allowed");

    /* Attacker changing IPs: each IP stays under the per-IP limit,
     * but the per-account window still catches it. */
    detector_init(&d);
    v = V_ALLOW;
    char ip[24];
    for (int i = 0; i < ACCOUNT_LIMIT; i++) {
        snprintf(ip, sizeof ip, "9.9.%d.1", i);
        event_make(&e, 100 + i, ip, "admin", EV_LOGIN_FAIL, "login");
        v = detector_process(&d, &e);
    }
    CHECK(v == V_DISTRIBUTED_BRUTE, "brute force from many IPs caught");
}

static void test_simulation(void)
{
    SimStats a, b;
    printf("Simulation\n");
    sim_run(0, 0, 42, &a);
    sim_run(0, 0, 42, &b);
    CHECK(a.actions > 0, "the bot attacked");
    CHECK(a.detected + a.missed == a.actions, "every action is counted once");
    CHECK(a.detected == b.detected && a.missed == b.missed, "same seed gives the same result");
}

int main(void)
{
    test_hash();
    test_input_rules();
    test_userdb();
    test_access();
    test_window_and_kmp();
    test_detector();
    test_simulation();

    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
