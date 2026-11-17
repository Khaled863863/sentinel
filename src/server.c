/*
 * Sentinel server (Part 3, bonus): network programming + multithreading.
 *
 * Usage: ./sentinel-server [port]
 *
 * - Every client gets its own thread.
 * - All threads share the user database, the intrusion detector, the audit log
 *   and the list of open connections. Each one is protected by a mutex, so two
 *   clients can never change the same data at the same time.
 * - Messages are encrypted with the XOR cipher from net.c.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "access.h"
#include "auth.h"
#include "ids.h"
#include "input.h"
#include "logger.h"
#include "net.h"

#define MAX_CLIENTS 32

typedef struct {
    int fd;
    char ip[INET_ADDRSTRLEN];
} Client;

/* Shared data and the locks that protect it. */
static UserDB g_db;
static pthread_mutex_t g_db_lock = PTHREAD_MUTEX_INITIALIZER;

static Detector g_detector;
static pthread_mutex_t g_detector_lock = PTHREAD_MUTEX_INITIALIZER;

static int g_client_fds[MAX_CLIENTS];
static int g_client_count = 0;
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

static char g_db_path[512];
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ------------------------------------------------------------------ */

static int add_client_fd(int fd)
{
    int ok = 0;
    pthread_mutex_lock(&g_clients_lock);
    if (g_client_count < MAX_CLIENTS) {
        g_client_fds[g_client_count++] = fd;
        ok = 1;
    }
    pthread_mutex_unlock(&g_clients_lock);
    return ok;
}

static void remove_client_fd(int fd)
{
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_client_count; i++) {
        if (g_client_fds[i] == fd) {
            g_client_fds[i] = g_client_fds[--g_client_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
}

static int client_count(void)
{
    pthread_mutex_lock(&g_clients_lock);
    int n = g_client_count;
    pthread_mutex_unlock(&g_clients_lock);
    return n;
}

/* Sends one event to the shared detector (under its lock) and logs alerts. */
static Verdict check_event(const char *ip, const char *user, EventType type, const char *payload)
{
    Event e;
    event_make(&e, (long)time(NULL), ip, user, type, payload);

    pthread_mutex_lock(&g_detector_lock);
    Verdict v = detector_process(&g_detector, &e);
    pthread_mutex_unlock(&g_detector_lock);

    if (v != V_ALLOW && v != V_BLOCKED) {
        log_event(LOG_ALERT, user, "intrusion detector: %s from %s", verdict_name(v), ip);
    }
    return v;
}

static void save_db_locked(void)
{
    if (userdb_save(&g_db, g_db_path) != 0) {
        log_event(LOG_WARN, NULL, "could not save the user database");
    }
}

/* Finds a feature by its number (1-6). Returns -1 if invalid. */
static int parse_resource(const char *text)
{
    char *end = NULL;
    long n = strtol(text, &end, 10);
    if (end == text || *end != '\0' || n < 1 || n > RES_COUNT) {
        return -1;
    }
    return (int)(n - 1);
}

static void send_help(int fd, const char *key)
{
    char msg[MAX_FRAME];
    int len = snprintf(msg, sizeof msg,
                       "Commands:\n"
                       "  REGISTER <user> <password>\n"
                       "  LOGIN <user> <password>\n"
                       "  WHOAMI\n"
                       "  REQUEST <number>   (use a feature, see the list below)\n"
                       "  SEARCH <text>      (send a search request)\n"
                       "  LOGOUT\n"
                       "  QUIT\n"
                       "Features:\n");
    for (int r = 0; r < RES_COUNT && len > 0 && (size_t)len < sizeof msg; r++) {
        len += snprintf(msg + len, sizeof msg - (size_t)len, "  %d. %s\n", r + 1,
                        resource_name((Resource)r));
    }
    send_frame(fd, msg, key);
}

static void *client_thread(void *arg)
{
    Client c = *(Client *)arg;
    free(arg);

    /* Only the main thread handles Ctrl+C, so g_stop is written and read by one thread.
     * Client threads are woken up at shutdown when their socket is shut down. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block, NULL);

    const char *key = net_key();
    char line[MAX_FRAME + 1];
    char reply[MAX_FRAME];
    char user[MAX_USERNAME + 1] = "";
    int logged_in = 0;

    log_event(LOG_INFO, NULL, "client connected from %s", c.ip);
    send_frame(c.fd, "Welcome to the Sentinel server. Type HELP for the commands.", key);

    for (;;) {
        int n = recv_frame(c.fd, line, sizeof line, key);
        if (n <= 0) {
            break;
        }

        char cmd[16] = "", arg1[64] = "", arg2[64] = "";
        int parts = sscanf(line, "%15s %63s %63s", cmd, arg1, arg2);
        if (parts < 1) {
            send_frame(c.fd, "Empty command. Type HELP.", key);
            continue;
        }

        const char *who = logged_in ? user : "-";

        /* Every command counts as a request (catches floods). Passwords are never sent to the detector or the log. */
        Verdict v = check_event(c.ip, who, EV_REQUEST, cmd);
        if (v != V_ALLOW) {
            snprintf(reply, sizeof reply, "BLOCKED by the intrusion detector (%s). Goodbye.", verdict_name(v));
            send_frame(c.fd, reply, key);
            break;
        }

        if (strcmp(cmd, "HELP") == 0) {
            send_help(c.fd, key);

        } else if (strcmp(cmd, "REGISTER") == 0) {
            if (parts < 3 || !is_valid_username(arg1) || !is_valid_password(arg2)) {
                send_frame(c.fd, "Usage: REGISTER <user> <password> (3-16 letters/digits/_, password 6-32 chars)", key);
                continue;
            }
            pthread_mutex_lock(&g_db_lock);
            Role role = (g_db.count == 0) ? ROLE_ADMIN : ROLE_USER;
            int rc = userdb_add(&g_db, arg1, arg2, role);
            if (rc == 0) {
                save_db_locked();
            }
            pthread_mutex_unlock(&g_db_lock);
            secure_zero(arg2, sizeof arg2);

            if (rc == 0) {
                log_event(LOG_INFO, arg1, "account created over the network from %s", c.ip);
                snprintf(reply, sizeof reply, "OK: account %s created (role %s).", arg1, role_name(role));
            } else {
                snprintf(reply, sizeof reply, "ERROR: that username is taken.");
            }
            send_frame(c.fd, reply, key);

        } else if (strcmp(cmd, "LOGIN") == 0) {
            if (parts < 3 || !is_valid_username(arg1)) {
                send_frame(c.fd, "Usage: LOGIN <user> <password>", key);
                continue;
            }
            long idx;
            time_t now = time(NULL);
            Role role = ROLE_GUEST;
            long wait = 0;

            pthread_mutex_lock(&g_db_lock);
            AuthResult res = auth_login(&g_db, arg1, arg2, now, &idx);
            if (idx >= 0) {
                role = g_db.users[idx].role;
                wait = auth_lock_remaining(&g_db.users[idx], now);
                save_db_locked();
            }
            pthread_mutex_unlock(&g_db_lock);
            secure_zero(arg2, sizeof arg2);

            v = check_event(c.ip, arg1, res == AUTH_OK ? EV_LOGIN_OK : EV_LOGIN_FAIL, "login");

            if (res == AUTH_OK) {
                logged_in = 1;
                memcpy(user, arg1, strlen(arg1) + 1); /* fits: is_valid_username checked the length */
                log_event(LOG_INFO, user, "logged in from %s", c.ip);
                snprintf(reply, sizeof reply, "OK: welcome %s (role %s).", user, role_name(role));
            } else if (res == AUTH_LOCKED || res == AUTH_NOW_LOCKED) {
                log_event(LOG_WARN, arg1, "login on locked account from %s", c.ip);
                snprintf(reply, sizeof reply, "ERROR: account locked for %ld seconds.", wait);
            } else {
                log_event(LOG_WARN, arg1, "failed login from %s", c.ip);
                snprintf(reply, sizeof reply, "ERROR: wrong username or password.");
            }
            if (v != V_ALLOW) {
                snprintf(reply, sizeof reply, "BLOCKED by the intrusion detector (%s). Goodbye.", verdict_name(v));
                send_frame(c.fd, reply, key);
                break;
            }
            send_frame(c.fd, reply, key);

        } else if (strcmp(cmd, "WHOAMI") == 0) {
            if (!logged_in) {
                send_frame(c.fd, "You are not logged in (guest).", key);
                continue;
            }
            pthread_mutex_lock(&g_db_lock);
            long idx = userdb_find(&g_db, user);
            Role role = idx >= 0 ? g_db.users[idx].role : ROLE_GUEST;
            pthread_mutex_unlock(&g_db_lock);
            snprintf(reply, sizeof reply, "You are %s (role %s), connected from %s.", user, role_name(role), c.ip);
            send_frame(c.fd, reply, key);

        } else if (strcmp(cmd, "REQUEST") == 0) {
            int res = parse_resource(arg1);
            if (res < 0) {
                send_frame(c.fd, "Usage: REQUEST <1-6>. Type HELP for the list.", key);
                continue;
            }
            Role role = ROLE_GUEST;
            if (logged_in) {
                pthread_mutex_lock(&g_db_lock);
                long idx = userdb_find(&g_db, user);
                if (idx >= 0) {
                    role = g_db.users[idx].role;
                }
                pthread_mutex_unlock(&g_db_lock);
            }
            if (access_allowed(role, (Resource)res)) {
                log_event(LOG_INFO, who, "remote use of %s", resource_name((Resource)res));
                snprintf(reply, sizeof reply, "ALLOWED: %s.", resource_name((Resource)res));
                send_frame(c.fd, reply, key);
            } else {
                log_event(LOG_WARN, who, "remote access denied: %s", resource_name((Resource)res));
                v = check_event(c.ip, who, EV_ACCESS_DENIED, resource_name((Resource)res));
                if (v != V_ALLOW) {
                    snprintf(reply, sizeof reply, "BLOCKED by the intrusion detector (%s). Goodbye.", verdict_name(v));
                    send_frame(c.fd, reply, key);
                    break;
                }
                snprintf(reply, sizeof reply, "DENIED: a %s cannot use %s.", role_name(role),
                         resource_name((Resource)res));
                send_frame(c.fd, reply, key);
            }

        } else if (strcmp(cmd, "SEARCH") == 0) {
            const char *text = line + strlen("SEARCH");
            while (*text == ' ') {
                text++;
            }
            v = check_event(c.ip, who, EV_REQUEST, text);
            if (v != V_ALLOW) {
                snprintf(reply, sizeof reply, "BLOCKED by the intrusion detector (%s). Goodbye.", verdict_name(v));
                send_frame(c.fd, reply, key);
                break;
            }
            snprintf(reply, sizeof reply, "No results for \"%.60s\".", text);
            send_frame(c.fd, reply, key);

        } else if (strcmp(cmd, "LOGOUT") == 0) {
            if (logged_in) {
                log_event(LOG_INFO, user, "logged out (network)");
            }
            logged_in = 0;
            user[0] = '\0';
            send_frame(c.fd, "OK: logged out.", key);

        } else if (strcmp(cmd, "QUIT") == 0) {
            send_frame(c.fd, "Goodbye.", key);
            break;

        } else {
            send_frame(c.fd, "Unknown command. Type HELP.", key);
        }
    }

    log_event(LOG_INFO, logged_in ? user : NULL, "client %s disconnected", c.ip);
    remove_client_fd(c.fd);
    close(c.fd);
    return NULL;
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return 1;
    }
    if (argc == 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[1]);
            return 1;
        }
    }

    const char *dir = getenv("SENTINEL_DIR");
    char log_path[512];
    if (dir == NULL || dir[0] == '\0') {
        dir = ".";
    }
    snprintf(g_db_path, sizeof g_db_path, "%s/users.db", dir);
    snprintf(log_path, sizeof log_path, "%s/sentinel.log", dir);

    if (logger_open(log_path) != 0) {
        fprintf(stderr, "Warning: running without an audit log.\n");
    }
    userdb_init(&g_db);
    if (userdb_load(&g_db, g_db_path) != 0) {
        logger_close();
        return 1;
    }
    detector_init(&g_detector);

    /* Ctrl+C stops the server cleanly. No SA_RESTART, so accept() wakes up. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); /* a client that disconnects must not kill the server */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        userdb_free(&g_db);
        logger_close();
        return 1;
    }
    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(listen_fd, 8) < 0) {
        perror("bind/listen");
        close(listen_fd);
        userdb_free(&g_db);
        logger_close();
        return 1;
    }

    printf("Sentinel server listening on port %d (Ctrl+C to stop)\n", port);
    log_event(LOG_INFO, NULL, "server started on port %d", port);

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof peer;
        int fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (fd < 0) {
            if (errno != EINTR) {
                perror("accept");
            }
            continue;
        }

        Client *c = malloc(sizeof *c);
        if (c == NULL || !add_client_fd(fd)) {
            free(c);
            send_frame(fd, "Server is full, try again later.", net_key());
            close(fd);
            continue;
        }
        c->fd = fd;
        inet_ntop(AF_INET, &peer.sin_addr, c->ip, sizeof c->ip);

        /* Block Ctrl+C while creating the thread, so the new thread starts with it blocked. */
        sigset_t block, old;
        sigemptyset(&block);
        sigaddset(&block, SIGINT);
        sigaddset(&block, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &block, &old);

        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&thread, &attr, client_thread, c);
        pthread_attr_destroy(&attr);
        pthread_sigmask(SIG_SETMASK, &old, NULL);

        if (rc != 0) {
            fprintf(stderr, "pthread_create failed\n");
            remove_client_fd(fd);
            close(fd);
            free(c);
        }
    }

    /* Shutting down: wake up every client thread and wait for them to finish. */
    printf("\nStopping the server...\n");
    close(listen_fd);
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_client_count; i++) {
        shutdown(g_client_fds[i], SHUT_RDWR);
    }
    pthread_mutex_unlock(&g_clients_lock);

    for (int waited = 0; client_count() > 0 && waited < 50; waited++) {
        struct timespec ts = { 0, 100000000L }; /* 0.1 s */
        nanosleep(&ts, NULL);
    }

    pthread_mutex_lock(&g_db_lock);
    save_db_locked();
    userdb_free(&g_db);
    pthread_mutex_unlock(&g_db_lock);
    log_event(LOG_INFO, NULL, "server stopped");
    logger_close();
    return 0;
}
