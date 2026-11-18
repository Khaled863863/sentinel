#ifndef INPUT_H
#define INPUT_H

#include <stddef.h>

/*
 * Safe input helpers.
 * Every piece of text the user types goes through these functions,
 * so a long line can never overflow a buffer (no gets, no bare scanf("%s")).
 */

/* Reads one line into buf (at most size - 1 characters) and removes the newline.
 * Returns 1 on success, 0 if the line was too long (the rest is thrown away),
 * and -1 on end of input. */
int read_line(char *buf, size_t size);

/* Same as read_line, but hides the typed characters when reading from a terminal. */
int read_password(char *buf, size_t size);

/* Prints prompt and reads a whole number between min and max (asks again on bad input).
 * Returns 1 on success and -1 on end of input. */
int read_int(const char *prompt, int min, int max, int *out);

/* 1 once stdin has reached end of input (used to leave all menus cleanly). */
int input_closed(void);

/* Username: 3-16 characters, letters, digits or '_'. */
int is_valid_username(const char *s);

/* Password: 6-32 visible characters, no spaces. */
int is_valid_password(const char *s);

/* Waits until the user presses Enter. */
void wait_for_enter(void);

#endif
