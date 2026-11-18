#ifndef UI_H
#define UI_H

#include "access.h"

/* ANSI colors (work on the Linux console and most terminals). */
#define CLR_RESET  "\033[0m"
#define CLR_BOLD   "\033[1m"
#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_CYAN   "\033[36m"
#define CLR_GRAY   "\033[90m"

void ui_clear(void);
void ui_banner(void);
void ui_separator(void);

/* Draws the access table (features x roles).
 * The column of the current role is highlighted, and the row of the
 * last action is marked green (allowed) or red (denied). last_res = -1 for none. */
void ui_access_table(Role current, int last_res, int last_allowed);

#endif
