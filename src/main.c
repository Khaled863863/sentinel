/*
 * Sentinel - a console host security system (CMPS 241 project).
 *
 * Part 1: login with salted password hashing, account lockout,
 *         role-based access control, audit log.
 * Part 2: attack simulation - an adaptive attacker bot against our intrusion detector.
 * Part 3: see server.c and client.c (network version, bonus).
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "access.h"
#include "auth.h"
#include "ids.h"
#include "input.h"
#include "logger.h"
#include "simulation.h"
#include "ui.h"

#define CONSOLE_SOURCE "console"
#define TEXT_LEN 64

static UserDB g_db;
static Detector g_live; /* watches what happens on this terminal */
static char g_db_path[512];
static char g_log_path[512];

/* Data files go in $SENTINEL_DIR (or the current folder). */
static void build_paths(void)
{
    const char *dir = getenv("SENTINEL_DIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = ".";
    }
    snprintf(g_db_path, sizeof g_db_path, "%s/users.db", dir);
    snprintf(g_log_path, sizeof g_log_path, "%s/sentinel.log", dir);
}

static void save_db(void)
{
    if (userdb_save(&g_db, g_db_path) != 0) {
        printf(CLR_RED "Warning: the user database could not be saved." CLR_RESET "\n");
    }
}

/* The detector source for a logged-in user on this terminal, e.g. "console:rawad".
 * Logins use plain "console", so blocking one user's session does not block logins. */
static void session_source(const char *user, char *out, size_t size)
{
    snprintf(out, size, "%s:%s", CONSOLE_SOURCE, user);
}

/* Sends an event from this terminal to the live detector and logs any alert. */
static Verdict watch_console(const char *source, const char *user, EventType type, const char *payload)
{
    Event e;
    event_make(&e, (long)time(NULL), source, user, type, payload);
    Verdict v = detector_process(&g_live, &e);
    if (v != V_ALLOW && v != V_BLOCKED) {
        log_event(LOG_ALERT, user, "intrusion detector: %s on the console", verdict_name(v));
    }
    return v;
}

/* Reads a line with a prompt. Returns 1 ok, 0 too long, -1 end of input. */
static int prompt_line(const char *prompt, char *buf, size_t size, int hidden)
{
    printf("%s", prompt);
    fflush(stdout);
    return hidden ? read_password(buf, size) : read_line(buf, size);
}

/* ------------------------------------------------------------------
 * Account screens
 * ---------------------------------------------------------------- */

static void do_register(void)
{
    char name[TEXT_LEN], pw[TEXT_LEN], again[TEXT_LEN];

    ui_clear();
    ui_banner();
    printf(CLR_BOLD "CREATE AN ACCOUNT" CLR_RESET "\n\n");

    int r = prompt_line("Username (3-16 letters, digits or _): ", name, sizeof name, 0);
    if (r < 0) {
        return;
    }
    if (r == 0 || !is_valid_username(name)) {
        printf(CLR_RED "That username is not valid." CLR_RESET "\n");
        wait_for_enter();
        return;
    }
    if (userdb_find(&g_db, name) >= 0) {
        printf(CLR_RED "That username is already taken." CLR_RESET "\n");
        wait_for_enter();
        return;
    }

    r = prompt_line("Password (6-32 characters, no spaces): ", pw, sizeof pw, 1);
    if (r < 0) {
        return;
    }
    if (r == 0 || !is_valid_password(pw)) {
        printf(CLR_RED "That password is not valid." CLR_RESET "\n");
        secure_zero(pw, sizeof pw);
        wait_for_enter();
        return;
    }
    r = prompt_line("Type the password again: ", again, sizeof again, 1);
    if (r < 0 || strcmp(pw, again) != 0) {
        printf(CLR_RED "The passwords do not match." CLR_RESET "\n");
        secure_zero(pw, sizeof pw);
        secure_zero(again, sizeof again);
        wait_for_enter();
        return;
    }

    /* The very first account becomes the administrator. */
    Role role = (g_db.count == 0) ? ROLE_ADMIN : ROLE_USER;
    int rc = userdb_add(&g_db, name, pw, role);
    secure_zero(pw, sizeof pw);
    secure_zero(again, sizeof again);

    if (rc == 0) {
        save_db();
        log_event(LOG_INFO, name, "account created (role %s)", role_name(role));
        printf(CLR_GREEN "Account created. Your role is %s." CLR_RESET "\n", role_name(role));
        if (role == ROLE_ADMIN) {
            printf("You are the first user, so you are the administrator.\n");
        }
    } else {
        printf(CLR_RED "Could not create the account." CLR_RESET "\n");
    }
    wait_for_enter();
}

static void show_profile(const char *me, int guest)
{
    ui_clear();
    printf(CLR_BOLD "MY PROFILE" CLR_RESET "\n");
    ui_separator();
    if (guest) {
        printf("You are using a guest session (no account).\n");
        printf("Role: Guest\n");
    } else {
        long i = userdb_find(&g_db, me);
        if (i >= 0) {
            const User *u = &g_db.users[i];
            printf("Username:          %s\n", u->username);
            printf("Role:              %s\n", role_name(u->role));
            printf("Failed attempts:   %d of %d\n", u->failed_attempts, MAX_FAILED_ATTEMPTS);
            printf("Password storage:  salt %s, hash %s\n", u->salt, u->hash);
            printf("(We never store your password, only a salted hash of it.)\n");
        }
    }
    wait_for_enter();
}

static void change_password(const char *me)
{
    char old_pw[TEXT_LEN], new_pw[TEXT_LEN], again[TEXT_LEN];
    long idx;

    ui_clear();
    printf(CLR_BOLD "CHANGE MY PASSWORD" CLR_RESET "\n");
    ui_separator();

    if (prompt_line("Current password: ", old_pw, sizeof old_pw, 1) < 0) {
        return;
    }
    AuthResult res = auth_login(&g_db, me, old_pw, time(NULL), &idx);
    secure_zero(old_pw, sizeof old_pw);
    if (res != AUTH_OK) {
        save_db();
        log_event(LOG_WARN, me, "wrong current password while changing password");
        printf(CLR_RED "Wrong password." CLR_RESET "\n");
        if (res == AUTH_NOW_LOCKED) {
            printf(CLR_RED "Too many wrong passwords: your account is now locked for %d seconds." CLR_RESET "\n",
                   LOCKOUT_SECONDS);
        }
        wait_for_enter();
        return;
    }

    int r1 = prompt_line("New password (6-32 characters, no spaces): ", new_pw, sizeof new_pw, 1);
    int r2 = (r1 > 0) ? prompt_line("Type it again: ", again, sizeof again, 1) : -1;
    if (r1 > 0 && r2 > 0 && is_valid_password(new_pw) && strcmp(new_pw, again) == 0) {
        auth_change_password(&g_db, idx, new_pw);
        save_db();
        log_event(LOG_INFO, me, "password changed");
        printf(CLR_GREEN "Password changed." CLR_RESET "\n");
    } else {
        printf(CLR_RED "Not changed: the password is not valid or the two do not match." CLR_RESET "\n");
    }
    secure_zero(new_pw, sizeof new_pw);
    secure_zero(again, sizeof again);
    wait_for_enter();
}

static void view_report(void)
{
    int per_role[ROLE_COUNT] = { 0 };
    int locked = 0;
    time_t now = time(NULL);

    for (size_t i = 0; i < g_db.count; i++) {
        per_role[g_db.users[i].role]++;
        if (auth_lock_remaining(&g_db.users[i], now) > 0) {
            locked++;
        }
    }

    ui_clear();
    printf(CLR_BOLD "SECURITY REPORT" CLR_RESET "\n");
    ui_separator();
    printf("Accounts: %zu (admins %d, users %d)\n", g_db.count, per_role[ROLE_ADMIN], per_role[ROLE_USER]);
    printf("Locked accounts right now: %d\n", locked);
    printf("Alerts raised on this console: %ld\n", g_live.alerts);
    ui_separator();

    SimStats s;
    if (sim_get_last(&s)) {
        printf("Last attack simulation:\n\n");
        sim_print_summary(&s);
    } else {
        printf("No attack simulation has been run yet.\n");
    }
    wait_for_enter();
}

static void read_log(void)
{
    ui_clear();
    printf(CLR_BOLD "AUDIT LOG (last 20 lines)" CLR_RESET "\n");
    ui_separator();
    logger_print_tail(20);
    wait_for_enter();
}

static void list_users(void)
{
    time_t now = time(NULL);
    printf(CLR_BOLD "%-18s %-7s %-8s %s" CLR_RESET "\n", "Username", "Role", "Failed", "Status");
    for (size_t i = 0; i < g_db.count; i++) {
        const User *u = &g_db.users[i];
        long left = auth_lock_remaining(u, now);
        printf("%-18s %-7s %-8d ", u->username, role_name(u->role), u->failed_attempts);
        if (left > 0) {
            printf(CLR_RED "locked (%lds)" CLR_RESET "\n", left);
        } else {
            printf(CLR_GREEN "active" CLR_RESET "\n");
        }
    }
}

static void manage_users(const char *me)
{
    char name[TEXT_LEN];
    char message[160] = "";

    for (;;) {
        ui_clear();
        printf(CLR_BOLD "MANAGE USERS" CLR_RESET "\n");
        ui_separator();
        list_users();
        ui_separator();
        if (message[0] != '\0') {
            printf("%s\n\n", message);
        }
        printf("1. Change a user's role\n2. Unlock an account\n3. Delete an account\n0. Back\n");

        int choice;
        if (read_int("Choose: ", 0, 3, &choice) < 0 || choice == 0) {
            return;
        }
        if (prompt_line("Username: ", name, sizeof name, 0) <= 0) {
            continue;
        }
        long i = userdb_find(&g_db, name);
        if (i < 0) {
            snprintf(message, sizeof message, CLR_RED "No such user." CLR_RESET);
            continue;
        }
        if (strcmp(name, me) == 0 && choice != 2) {
            snprintf(message, sizeof message, CLR_RED "You cannot change or delete your own account here." CLR_RESET);
            continue;
        }

        if (choice == 1) {
            int role;
            if (read_int("New role (0 = Admin, 1 = User): ", 0, 1, &role) < 0) {
                return;
            }
            g_db.users[i].role = (Role)role;
            log_event(LOG_INFO, me, "changed role of %s to %s", name, role_name((Role)role));
            snprintf(message, sizeof message, CLR_GREEN "%s is now %s." CLR_RESET, name, role_name((Role)role));
        } else if (choice == 2) {
            g_db.users[i].locked_until = 0;
            g_db.users[i].failed_attempts = 0;
            log_event(LOG_INFO, me, "unlocked %s", name);
            snprintf(message, sizeof message, CLR_GREEN "%s is unlocked." CLR_RESET, name);
        } else {
            userdb_remove(&g_db, name);
            log_event(LOG_WARN, me, "deleted account %s", name);
            snprintf(message, sizeof message, CLR_GREEN "%s was deleted." CLR_RESET, name);
        }
        save_db();
    }
}

static void simulation_menu(const char *me)
{
    for (;;) {
        ui_clear();
        printf(CLR_BOLD "ATTACK SIMULATION" CLR_RESET "\n");
        ui_separator();
        printf("An attacker bot tries to break in while our intrusion detector defends.\n");
        printf("The detector scores when it catches an attack, the attacker scores when\n");
        printf("an attack gets through. Cracking the admin password wins at once.\n\n");
        printf("1. Watch the bot attack (live)\n");
        printf("2. Run quickly and show the results\n");
        printf("3. You are the attacker\n");
        printf("0. Back\n");

        int choice;
        if (read_int("Choose: ", 0, 3, &choice) < 0 || choice == 0) {
            return;
        }

        if (choice == 3) {
            sim_human_mode();
            wait_for_enter();
            continue;
        }

        const char *seed_text = getenv("SENTINEL_SEED");
        unsigned seed = seed_text ? (unsigned)strtoul(seed_text, NULL, 10) : (unsigned)time(NULL);
        SimStats stats;
        sim_run(choice == 1, 120, seed, &stats);
        log_event(LOG_INFO, me, "simulation: detector %d, attacker %d, false alarms %d, cracked=%d",
                  stats.detected, stats.missed, stats.false_alarms, stats.cracked);
        printf("\n");
        sim_print_summary(&stats);
        wait_for_enter();
    }
}

/* ------------------------------------------------------------------
 * Logged-in session: the access table is redrawn after every action.
 * ---------------------------------------------------------------- */

static void run_session(const char *username, int guest)
{
    char me[MAX_USERNAME + 1];
    char message[200] = "Welcome! Choose an action. Denied actions are logged.";
    int last_res = -1;
    int last_allowed = 0;

    char source[EV_SOURCE_LEN];

    snprintf(me, sizeof me, "%s", username);
    session_source(me, source, sizeof source);

    long blocked = detector_blocked_for(&g_live, source, (long)time(NULL));
    if (blocked > 0) {
        printf(CLR_RED "\nThe intrusion detector has blocked this session for %ld more seconds." CLR_RESET "\n",
               blocked);
        wait_for_enter();
        return;
    }

    while (!input_closed()) {
        Role role = ROLE_GUEST;
        if (!guest) {
            long i = userdb_find(&g_db, me);
            if (i < 0) {
                return; /* account was deleted */
            }
            role = g_db.users[i].role;
        }

        ui_clear();
        ui_banner();
        printf("Logged in as " CLR_BOLD "%s" CLR_RESET " (%s)\n\n", me, role_name(role));
        ui_access_table(role, last_res, last_allowed);
        printf("\n%s\n\n", message);
        for (int r = 0; r < RES_COUNT; r++) {
            printf("%d. %s\n", r + 1, resource_name((Resource)r));
        }
        printf("0. Log out\n");

        int choice;
        if (read_int("Choose an action: ", 0, RES_COUNT, &choice) < 0) {
            return;
        }
        if (choice == 0) {
            log_event(LOG_INFO, me, "logged out");
            return;
        }

        Resource res = (Resource)(choice - 1);
        last_res = (int)res;

        /* The core check: is this action allowed for this role? O(1). */
        if (!access_allowed(role, res)) {
            last_allowed = 0;
            snprintf(message, sizeof message, CLR_RED "Access denied: a %s cannot use \"%s\"." CLR_RESET,
                     role_name(role), resource_name(res));
            log_event(LOG_WARN, me, "access denied: %s", resource_name(res));

            Verdict v = watch_console(source, me, EV_ACCESS_DENIED, resource_name(res));
            if (v != V_ALLOW) {
                printf(CLR_RED "\nThe intrusion detector noticed repeated attempts to use restricted"
                       "\nfeatures (%s). You have been logged out." CLR_RESET "\n", verdict_name(v));
                wait_for_enter();
                return;
            }
            continue;
        }

        last_allowed = 1;
        log_event(LOG_INFO, me, "used: %s", resource_name(res));
        switch (res) {
        case RES_VIEW_PROFILE:    show_profile(me, guest); break;
        case RES_CHANGE_PASSWORD: change_password(me); break;
        case RES_VIEW_REPORT:     view_report(); break;
        case RES_RUN_SIMULATION:  simulation_menu(me); break;
        case RES_READ_LOG:        read_log(); break;
        case RES_MANAGE_USERS:    manage_users(me); break;
        case RES_COUNT:           break;
        }
        snprintf(message, sizeof message, CLR_GREEN "Last action allowed: %s" CLR_RESET, resource_name(res));
    }
}

static void do_login(void)
{
    char name[TEXT_LEN], pw[TEXT_LEN];
    time_t now = time(NULL);

    ui_clear();
    ui_banner();
    printf(CLR_BOLD "LOG IN" CLR_RESET "\n\n");

    long blocked = detector_blocked_for(&g_live, CONSOLE_SOURCE, (long)now);
    if (blocked > 0) {
        printf(CLR_RED "Too many failed logins from this terminal.\n"
               "The intrusion detector has blocked logins for %ld more seconds." CLR_RESET "\n", blocked);
        wait_for_enter();
        return;
    }

    if (prompt_line("Username: ", name, sizeof name, 0) < 0) {
        return;
    }
    if (prompt_line("Password: ", pw, sizeof pw, 1) < 0) {
        return;
    }

    long idx;
    AuthResult res = auth_login(&g_db, name, pw, now, &idx);
    secure_zero(pw, sizeof pw);
    if (idx >= 0) {
        save_db(); /* failed-attempt counters may have changed */
    }

    Verdict v = watch_console(CONSOLE_SOURCE, name, res == AUTH_OK ? EV_LOGIN_OK : EV_LOGIN_FAIL, "login");

    switch (res) {
    case AUTH_OK:
        log_event(LOG_INFO, name, "logged in");
        run_session(name, 0);
        return;
    case AUTH_NO_SUCH_USER:
    case AUTH_WRONG_PASSWORD:
        /* Same message in both cases, so attackers cannot tell which usernames exist. */
        log_event(LOG_WARN, name, "failed login");
        printf(CLR_RED "Wrong username or password." CLR_RESET "\n");
        break;
    case AUTH_LOCKED:
        log_event(LOG_WARN, name, "login attempt on a locked account");
        printf(CLR_RED "This account is locked. Try again in %ld seconds." CLR_RESET "\n",
               auth_lock_remaining(&g_db.users[idx], now));
        break;
    case AUTH_NOW_LOCKED:
        log_event(LOG_ALERT, name, "account locked after %d wrong passwords", MAX_FAILED_ATTEMPTS);
        printf(CLR_RED "Too many wrong passwords. The account is locked for %d seconds." CLR_RESET "\n",
               LOCKOUT_SECONDS);
        break;
    }
    if (v != V_ALLOW) {
        printf(CLR_RED "Intrusion detector: %s. This terminal is blocked for %d seconds." CLR_RESET "\n",
               verdict_name(v), BLOCK_TICKS);
    }
    wait_for_enter();
}

static void show_about(void)
{
    ui_clear();
    ui_banner();
    printf("Sentinel is a small security system built for CMPS 241.\n\n");
    printf("- Passwords are stored as salted hashes, never as plain text.\n");
    printf("- An account locks for %d seconds after %d wrong passwords.\n", LOCKOUT_SECONDS, MAX_FAILED_ATTEMPTS);
    printf("- Admins, users and guests can use different features.\n");
    printf("- Every important action is written to an audit log.\n");
    printf("- An intrusion detector watches for attacks, and you can test it\n");
    printf("  against an attacker bot in the attack simulation.\n\n");
    printf(CLR_YELLOW "Note: the hash and cipher here are simple versions for learning.\n"
           "Real systems use bcrypt/Argon2 for passwords and TLS for networks." CLR_RESET "\n");
    wait_for_enter();
}

int main(void)
{
    build_paths();
    signal(SIGTSTP, SIG_IGN); /* no Ctrl+Z escape to a shell in kiosk mode */

    if (logger_open(g_log_path) != 0) {
        fprintf(stderr, "Warning: running without an audit log.\n");
    }
    userdb_init(&g_db);
    if (userdb_load(&g_db, g_db_path) != 0) {
        fprintf(stderr, "Could not load %s\n", g_db_path);
        logger_close();
        return 1;
    }
    detector_init(&g_live);
    log_event(LOG_INFO, NULL, "Sentinel started (%zu accounts)", g_db.count);

    while (!input_closed()) {
        ui_clear();
        ui_banner();
        if (g_db.count == 0) {
            printf(CLR_YELLOW "No accounts yet. The first account you create will be the administrator." CLR_RESET "\n\n");
        }
        printf("1. Log in\n");
        printf("2. Create an account\n");
        printf("3. Continue as guest\n");
        printf("4. About Sentinel\n");
        printf("0. Exit\n");

        int choice;
        if (read_int("Choose: ", 0, 4, &choice) < 0 || choice == 0) {
            break;
        }
        switch (choice) {
        case 1: do_login(); break;
        case 2: do_register(); break;
        case 3:
            log_event(LOG_INFO, "guest", "guest session started");
            run_session("guest", 1);
            break;
        case 4: show_about(); break;
        default: break;
        }
    }

    log_event(LOG_INFO, NULL, "Sentinel stopped");
    userdb_free(&g_db);
    logger_close();
    printf("\nGoodbye.\n");
    return 0;
}
