#ifndef ATTACKER_H
#define ATTACKER_H

#include "ids.h"

/*
 * The attacker bot (Sprint 2 "hard bot").
 *
 * Strategy:
 *  - It has 4 attack types and keeps a success rate for each one.
 *    It usually picks the type with the best rate, and sometimes (15%)
 *    tries a random one to keep learning (an "epsilon-greedy" strategy).
 *  - When it gets caught, its IP address is blocked, so it switches to a new IP,
 *    slows down (doubles the wait between attacks, up to 8 ticks) to stay
 *    under the detector's limits, and re-chooses its attack type.
 *  - For injections, it also remembers which payloads got through and reuses them.
 * The bot only ever produces valid events and never repeats a password guess
 * that was already tested.
 */

typedef enum {
    ATK_BRUTE_FORCE = 0,
    ATK_PRIV_ESC,
    ATK_FLOOD,
    ATK_INJECTION,
    ATK_COUNT
} AttackKind;

#define BOT_IP_COUNT 12 /* 4 addresses in each of 3 ranges */
#define BOT_MAX_DELAY 8
#define FLOOD_BURST 20
#define INJECTION_COUNT 8

/* Common passwords the bot tries against the "admin" account. */
extern const char *const COMMON_PASSWORDS[];
extern const int COMMON_PASSWORD_COUNT;
#define SIM_SECRET_INDEX 10 /* the simulated admin password is COMMON_PASSWORDS[10] */

typedef struct {
    char ips[BOT_IP_COUNT][EV_SOURCE_LEN];
    int current_ip;
    int ips_burned;
    int out_of_ips;

    int attempts[ATK_COUNT];
    int successes[ATK_COUNT];
    AttackKind kind;      /* attack type it is using now */
    AttackKind last_kind; /* attack type of the last action */
    int delay;            /* ticks between actions */
    long next_tick;

    int guess_index; /* next password to try */
    int cracked;     /* 1 if it found the admin password */

    int last_payload;
    int payload_ok[INJECTION_COUNT];
    int payload_caught[INJECTION_COUNT];
} AttackerBot;

void bot_init(AttackerBot *b);

/* Produces the events of one attack action (0 if it is not the bot's turn yet).
 * out must have room for FLOOD_BURST events. */
int bot_act(AttackerBot *b, long tick, Event *out, int max_out);

/* Tells the bot whether its last action was detected, so it can adapt. */
void bot_feedback(AttackerBot *b, int detected);

/* Normal users (alice, bob, carol) doing normal things. Returns 0 or 1 event. */
int benign_act(long tick, Event *out, int max_out);

const char *attack_name(AttackKind k);

#endif
