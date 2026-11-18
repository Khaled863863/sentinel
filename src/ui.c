#include "ui.h"

#include <stdio.h>

void ui_clear(void)
{
    printf("\033[2J\033[H");
}

void ui_separator(void)
{
    printf(CLR_GRAY "----------------------------------------------------------------------" CLR_RESET "\n");
}

void ui_banner(void)
{
    printf(CLR_CYAN CLR_BOLD);
    printf("  ____             _   _            _ \n");
    printf(" / ___|  ___ _ __ | |_(_)_ __   ___| |\n");
    printf(" \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |\n");
    printf("  ___) |  __/ | | | |_| | | | |  __/ |\n");
    printf(" |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|\n");
    printf(CLR_RESET);
    printf(CLR_GRAY "  Host security system - CMPS 241 project" CLR_RESET "\n");
    ui_separator();
}

void ui_access_table(Role current, int last_res, int last_allowed)
{
    printf(CLR_BOLD "  %-24s" CLR_RESET, "ACCESS TABLE");
    for (int r = 0; r < ROLE_COUNT; r++) {
        if (r == (int)current) {
            printf(CLR_CYAN CLR_BOLD " [%-5s]" CLR_RESET, role_name((Role)r));
        } else {
            printf("  %-5s ", role_name((Role)r));
        }
    }
    printf("\n");

    for (int res = 0; res < RES_COUNT; res++) {
        int is_last = (res == last_res);
        const char *row_color = !is_last ? "" : (last_allowed ? CLR_GREEN : CLR_RED);

        printf("%s%s %-24s" CLR_RESET, row_color, is_last ? ">" : " ",
               resource_name((Resource)res));
        for (int r = 0; r < ROLE_COUNT; r++) {
            int ok = access_allowed((Role)r, (Resource)res);
            if (r == (int)current) {
                printf("%s   %-3s  " CLR_RESET, ok ? CLR_GREEN CLR_BOLD : CLR_RED CLR_BOLD,
                       ok ? "yes" : "no");
            } else {
                printf(CLR_GRAY "   %-3s  " CLR_RESET, ok ? "yes" : "no");
            }
        }
        printf("\n");
    }
}
