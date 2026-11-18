#include "logger.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOG_LINE_MAX 256
#define LOG_TAIL_MAX 50

static FILE *g_log = NULL;
static char g_log_path[512];
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *level_name(LogLevel level)
{
    switch (level) {
    case LOG_INFO:  return "INFO ";
    case LOG_WARN:  return "WARN ";
    case LOG_ALERT: return "ALERT";
    }
    return "?????";
}

int logger_open(const char *path)
{
    pthread_mutex_lock(&g_log_lock);
    if (g_log != NULL) {
        fclose(g_log);
        g_log = NULL;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        perror(path);
        pthread_mutex_unlock(&g_log_lock);
        return -1;
    }
    g_log = fdopen(fd, "a");
    if (g_log == NULL) {
        perror(path);
        close(fd);
        pthread_mutex_unlock(&g_log_lock);
        return -1;
    }
    snprintf(g_log_path, sizeof g_log_path, "%s", path);
    pthread_mutex_unlock(&g_log_lock);
    return 0;
}

void logger_close(void)
{
    pthread_mutex_lock(&g_log_lock);
    if (g_log != NULL) {
        fclose(g_log);
        g_log = NULL;
    }
    pthread_mutex_unlock(&g_log_lock);
}

/* Replaces newlines and other control characters with '?'. */
static void sanitize(char *s)
{
    for (; *s != '\0'; s++) {
        if ((unsigned char)*s < 32 || (unsigned char)*s == 127) {
            *s = '?';
        }
    }
}

void log_event(LogLevel level, const char *user, const char *fmt, ...)
{
    char message[LOG_LINE_MAX];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof message, fmt, args);
    va_end(args);
    sanitize(message);

    char who[64];
    snprintf(who, sizeof who, "%s", (user != NULL && user[0] != '\0') ? user : "-");
    sanitize(who);

    time_t now = time(NULL);
    struct tm local;
    char stamp[32];
    localtime_r(&now, &local);
    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &local);

    pthread_mutex_lock(&g_log_lock);
    if (g_log != NULL) {
        fprintf(g_log, "%s [%s] user=%s %s\n", stamp, level_name(level), who, message);
        fflush(g_log);
    }
    pthread_mutex_unlock(&g_log_lock);
}

int logger_print_tail(int n)
{
    static char ring[LOG_TAIL_MAX][LOG_LINE_MAX];
    char path[512];

    if (n < 1) {
        n = 1;
    }
    if (n > LOG_TAIL_MAX) {
        n = LOG_TAIL_MAX;
    }

    pthread_mutex_lock(&g_log_lock);
    snprintf(path, sizeof path, "%s", g_log_path);
    pthread_mutex_unlock(&g_log_lock);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        perror(path);
        return -1;
    }

    /* Keep only the last n lines in a circular buffer. */
    long total = 0;
    char line[LOG_LINE_MAX];
    while (fgets(line, sizeof line, f) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) {
                /* skip the rest of a very long line */
            }
        }
        snprintf(ring[total % n], LOG_LINE_MAX, "%s", line);
        total++;
    }
    fclose(f);

    long start = total > n ? total - n : 0;
    for (long i = start; i < total; i++) {
        const char *l = ring[i % n];
        printf("%s", l);
        if (l[0] != '\0' && l[strlen(l) - 1] != '\n') {
            printf("\n");
        }
    }
    if (total == 0) {
        printf("(the log is empty)\n");
    }
    return 0;
}
