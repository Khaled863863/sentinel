#include "input.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int g_input_closed = 0;

int input_closed(void)
{
    return g_input_closed;
}

/* Throws away everything up to the end of the current line. */
static void discard_rest_of_line(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* skip */
    }
}

int read_line(char *buf, size_t size)
{
    if (buf == NULL || size < 2) {
        return -1;
    }
    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
        g_input_closed = 1;
        return -1;
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
        if (len > 0 && buf[len - 1] == '\r') {
            buf[--len] = '\0';
        }
        return 1;
    }
    if (feof(stdin)) {
        return 1; /* last line of the input had no newline */
    }

    /* The line did not fit: keep what fits, drop the rest. */
    discard_rest_of_line();
    return 0;
}

int read_password(char *buf, size_t size)
{
    struct termios old_settings;
    int hide = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_settings) == 0;

    if (hide) {
        struct termios quiet = old_settings;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }

    int result = read_line(buf, size);

    if (hide) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings);
        printf("\n");
    }
    return result;
}

int read_int(const char *prompt, int min, int max, int *out)
{
    char buf[32];

    for (;;) {
        printf("%s", prompt);
        fflush(stdout);

        int r = read_line(buf, sizeof buf);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            printf("That input is too long. Please try again.\n");
            continue;
        }

        char *end = NULL;
        errno = 0;
        long value = strtol(buf, &end, 10);
        while (end != NULL && isspace((unsigned char)*end)) {
            end++;
        }
        if (end == buf || errno == ERANGE || *end != '\0' || value < min || value > max) {
            printf("Please enter a number between %d and %d.\n", min, max);
            continue;
        }
        *out = (int)value;
        return 1;
    }
}

int is_valid_username(const char *s)
{
    size_t len = strlen(s);
    if (len < 3 || len > 16) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)s[i]) && s[i] != '_') {
            return 0;
        }
    }
    return 1;
}

int is_valid_password(const char *s)
{
    size_t len = strlen(s);
    if (len < 6 || len > 32) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isgraph((unsigned char)s[i])) {
            return 0;
        }
    }
    return 1;
}

void wait_for_enter(void)
{
    char buf[8];
    if (input_closed()) {
        return;
    }
    printf("\nPress Enter to continue...");
    fflush(stdout);
    (void)read_line(buf, sizeof buf);
}
