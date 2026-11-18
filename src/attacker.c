#include "attacker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *const COMMON_PASSWORDS[] = {
    "123456",    "password",  "123456789", "12345678",  "qwerty",
    "abc123",    "111111",    "1234567",   "iloveyou",  "admin",
    "welcome",   "monkey",    "dragon",    "football",  "sunshine",
    "princess",  "letmein",   "shadow",    "master",    "superman",
    "trustno1",  "baseball",  "starwars",  "passw0rd",  "beirut2026",
    "hello123",  "freedom",   "whatever",  "qazwsx",    "zaq12wsx",
};
const int COMMON_PASSWORD_COUNT = (int)(sizeof COMMON_PASSWORDS / sizeof COMMON_PASSWORDS[0]);

/* Injection payloads. The last ones are disguised to slip past the signatures. */
static const char *const INJECTIONS[INJECTION_COUNT] = {
    "id=1' OR '1'='1",
    "q=1 UNION SELECT password FROM users",
    "file=../../etc/passwd",
    "name=<script>alert(1)</script>",
    "cmd=x;rm -rf /tmp",
    "q=1; DROP TABLE users",
    "q=1 UN/**/ION SEL/**/ECT pass FROM users",
    "file=..%2f..%2fetc%2fpasswd",
};

static const char *const KIND_NAMES[ATK_COUNT] = {
    "brute force", "privilege escalation", "request flood", "injection",
};

const char *attack_name(AttackKind k)
{
    if ((int)k < 0 || k >= ATK_COUNT) {
        return "?";
    }
    return KIND_NAMES[k];
}

/* Laplace-smoothed success rate: (successes + 1) / (attempts + 2). */
static double rate(int successes, int attempts)
{
    return (successes + 1.0) / (attempts + 2.0);
}

/* Epsilon-greedy choice of attack type. O(ATK_COUNT). */
static AttackKind choose_kind(const AttackerBot *b)
{
    if (rand() % 100 < 15) {
        return (AttackKind)(rand() % ATK_COUNT);
    }
    AttackKind best = (AttackKind)(rand() % ATK_COUNT); /* random tie-break */
    for (int k = 0; k < ATK_COUNT; k++) {
        if (rate(b->successes[k], b->attempts[k]) > rate(b->successes[best], b->attempts[best])) {
            best = (AttackKind)k;
        }
    }
    return best;
}

/* Same idea for injection payloads: reuse what worked. O(INJECTION_COUNT). */
static int choose_payload(const AttackerBot *b)
{
    if (rand() % 100 < 20) {
        return rand() % INJECTION_COUNT;
    }
    int best = rand() % INJECTION_COUNT;
    for (int p = 0; p < INJECTION_COUNT; p++) {
        int tries = b->payload_ok[p] + b->payload_caught[p];
        int best_tries = b->payload_ok[best] + b->payload_caught[best];
        if (rate(b->payload_ok[p], tries) > rate(b->payload_ok[best], best_tries)) {
            best = p;
        }
    }
    return best;
}

void bot_init(AttackerBot *b)
{
    memset(b, 0, sizeof *b);
    static const char *const RANGES[] = { "203.0.113.", "198.51.100.", "192.0.2." };
    for (int i = 0; i < BOT_IP_COUNT; i++) {
        /* Mix the ranges so the bot does not use one range in a row. */
        snprintf(b->ips[i], EV_SOURCE_LEN, "%s%d", RANGES[i % 3], 10 + i * 7);
    }
    b->delay = 1;
    b->next_tick = 0;
    b->kind = choose_kind(b);
    b->last_kind = b->kind;
}

static void attack_event(Event *e, long tick, const char *ip, const char *user,
                         EventType type, const char *payload, AttackKind kind)
{
    event_make(e, tick, ip, user, type, payload);
    e->is_attack = 1;
    e->kind = (int)kind;
}

int bot_act(AttackerBot *b, long tick, Event *out, int max_out)
{
    if (b->out_of_ips || b->cracked || tick < b->next_tick || max_out < 1) {
        return 0;
    }

    const char *ip = b->ips[b->current_ip];
    char payload[EV_PAYLOAD_LEN];
    int n = 0;

    switch (b->kind) {
    case ATK_BRUTE_FORCE: {
        int correct = (b->guess_index == SIM_SECRET_INDEX);
        snprintf(payload, sizeof payload, "password=%s", COMMON_PASSWORDS[b->guess_index]);
        attack_event(&out[0], tick, ip, "admin", correct ? EV_LOGIN_OK : EV_LOGIN_FAIL,
                     payload, ATK_BRUTE_FORCE);
        n = 1;
        break;
    }
    case ATK_PRIV_ESC:
        attack_event(&out[0], tick, ip, "mallory", EV_ACCESS_DENIED, "GET /admin/users",
                     ATK_PRIV_ESC);
        n = 1;
        break;
    case ATK_FLOOD:
        n = max_out < FLOOD_BURST ? max_out : FLOOD_BURST;
        for (int i = 0; i < n; i++) {
            snprintf(payload, sizeof payload, "GET /search?page=%d", i);
            attack_event(&out[i], tick, ip, "-", EV_REQUEST, payload, ATK_FLOOD);
        }
        break;
    case ATK_INJECTION:
    case ATK_COUNT:
        b->last_payload = choose_payload(b);
        attack_event(&out[0], tick, ip, "-", EV_REQUEST, INJECTIONS[b->last_payload],
                     ATK_INJECTION);
        n = 1;
        break;
    }

    b->last_kind = b->kind;
    b->next_tick = tick + b->delay;
    return n;
}

void bot_feedback(AttackerBot *b, int detected)
{
    AttackKind k = b->last_kind;
    b->attempts[k]++;

    if (!detected) {
        b->successes[k]++;
        if (k == ATK_BRUTE_FORCE) {
            if (b->guess_index == SIM_SECRET_INDEX) {
                b->cracked = 1;
            } else if (b->guess_index < COMMON_PASSWORD_COUNT - 1) {
                b->guess_index++; /* only move on when the guess was really tested */
            }
        }
        if (k == ATK_INJECTION) {
            b->payload_ok[b->last_payload]++;
        }
        /* Sometimes explore another attack type even when things go well. */
        if (rand() % 100 < 10) {
            b->kind = choose_kind(b);
        }
        return;
    }

    /* Caught: the IP is now blocked. Switch IP, slow down, re-plan. */
    if (k == ATK_INJECTION) {
        b->payload_caught[b->last_payload]++;
    }
    b->ips_burned++;
    if (b->current_ip + 1 < BOT_IP_COUNT) {
        b->current_ip++;
    } else {
        b->out_of_ips = 1;
    }
    if (b->delay < BOT_MAX_DELAY) {
        b->delay *= 2;
    }
    b->kind = choose_kind(b);
}

int benign_act(long tick, Event *out, int max_out)
{
    static const char *const NAMES[] = { "alice", "bob", "carol" };
    static const char *const IPS[] = { "10.0.0.11", "10.0.0.12", "10.0.0.13" };

    if (max_out < 1 || rand() % 100 >= 30) {
        return 0;
    }
    int u = rand() % 3;
    int r = rand() % 100;

    if (r < 60) {
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_REQUEST, "GET /home");
    } else if (r < 75) {
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_LOGIN_OK, "login");
    } else if (r < 88) {
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_LOGIN_FAIL, "login (typo)");
    } else if (r < 96) {
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_ACCESS_OK, "GET /reports");
    } else if (r < 99) {
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_ACCESS_DENIED, "GET /admin/users");
    } else {
        /* An innocent search that looks like an attack: shows what a false alarm is. */
        event_make(&out[0], tick, IPS[u], NAMES[u], EV_REQUEST,
                   "search=how does union select work");
    }
    return 1;
}
