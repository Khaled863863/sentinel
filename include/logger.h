#ifndef LOGGER_H
#define LOGGER_H

/*
 * Audit log: every important event is written to a file with a timestamp.
 * The logger is protected by a mutex, so the multithreaded server can use it too.
 */

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ALERT
} LogLevel;

/* Opens (or creates) the log file in append mode. Returns 0 or -1. */
int logger_open(const char *path);

void logger_close(void);

/* Writes one line: time [LEVEL] user=NAME message.
 * Control characters (like newlines) are replaced, so nobody can forge fake log lines. */
void log_event(LogLevel level, const char *user, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Prints the last n lines of the log (n is capped at 50). Returns 0 or -1. */
int logger_print_tail(int n);

#endif
