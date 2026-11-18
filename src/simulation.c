#include "simulation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "input.h"
#include "logger.h"
#include "ui.h"

#define FEED_LINES 12
#define FEED_LEN 160

static SimStats g_last;
static int g_has_last = 0;

/* The last FEED_LINES lines shown on the screen (circular buffer). */
typedef struct {
    char lines[FEED_LINES][FEED_LEN];
    int count;
} Feed;

static void feed_add(Feed *f, const char *line)
{
    snprintf(f->lines[f->count % FEED_LINES], FEED_LEN, "%s", line);
    f->count++;
}

static void sleep_ms(int ms)
{
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void draw_screen(long tick, const SimStats *s, const AttackerBot *bot, const Feed *feed)
{
    ui_clear();
    printf(CLR_BOLD "ATTACK SIMULATION" CLR_RESET "   tick %ld / %d\n", tick, SIM_TICKS);
    ui_separator();
    printf(CLR_BOLD "Detector score: " CLR_GREEN "%-4d" CLR_RESET
           CLR_BOLD "   Attacker score: " CLR_RED "%-4d" CLR_RESET
           "   False alarms: %d\n", s->detected, s->missed, s->false_alarms);
    printf("Bot: strategy=%-20s ip=%-14s waits %d tick(s)   IPs burned %d/%d\n",
           attack_name(bot->kind), bot->out_of_ips ? "none" : bot->ips[bot->current_ip],
           bot->delay, bot->ips_burned, BOT_IP_COUNT);
    printf("Admin password guesses tested: %d/%d\n", bot->guess_index, COMMON_PASSWORD_COUNT);
    ui_separator();

    int start = feed->count > FEED_LINES ? feed->count - FEED_LINES : 0;
    for (int i = start; i < feed->count; i++) {
        printf("%s\n", feed->lines[i % FEED_LINES]);
    }
    fflush(stdout);
}

void sim_run(int watch, int delay_ms, unsigned seed, SimStats *out)
{
    static Detector det; /* about 90 KB: too big for the stack, so it is static */
    AttackerBot bot;
    Feed feed;
    Event events[FLOOD_BURST];
    char line[FEED_LEN];
    long tick;

    memset(out, 0, sizeof *out);
    memset(&feed, 0, sizeof feed);
    srand(seed);
    detector_init(&det);
    bot_init(&bot);

    for (tick = 1; tick <= SIM_TICKS && !bot.out_of_ips && !bot.cracked; tick++) {
        int changed = 0;

        /* Normal users. */
        int nb = benign_act(tick, events, FLOOD_BURST);
        for (int i = 0; i < nb; i++) {
            Verdict v = detector_process(&det, &events[i]);
            out->benign++;
            if (v != V_ALLOW && v != V_BLOCKED) {
                out->false_alarms++;
                snprintf(line, sizeof line, CLR_YELLOW "[%3ld] %-14s %-6s %-34.34s FALSE ALARM (%s)" CLR_RESET,
                         tick, events[i].source, events[i].username, events[i].payload, verdict_name(v));
            } else if (v == V_BLOCKED) {
                snprintf(line, sizeof line, CLR_YELLOW "[%3ld] %-14s %-6s %-34.34s blocked" CLR_RESET,
                         tick, events[i].source, events[i].username, events[i].payload);
            } else {
                snprintf(line, sizeof line, CLR_GRAY "[%3ld] %-14s %-6s %-34.34s ok" CLR_RESET,
                         tick, events[i].source, events[i].username, events[i].payload);
            }
            feed_add(&feed, line);
            changed = 1;
        }

        /* The attacker. */
        int na = bot_act(&bot, tick, events, FLOOD_BURST);
        if (na > 0) {
            Verdict first = V_ALLOW;
            for (int i = 0; i < na; i++) {
                Verdict v = detector_process(&det, &events[i]);
                if (first == V_ALLOW && v != V_ALLOW) {
                    first = v;
                }
            }
            AttackKind k = bot.last_kind;
            int detected = (first != V_ALLOW);
            out->actions++;
            out->kind_total[k]++;
            if (detected) {
                out->detected++;
                out->kind_detected[k]++;
                snprintf(line, sizeof line, CLR_GREEN "[%3ld] %-14s %-20s %-30.30s CAUGHT (%s)" CLR_RESET,
                         tick, events[0].source, attack_name(k), events[0].payload, verdict_name(first));
            } else {
                out->missed++;
                snprintf(line, sizeof line, CLR_RED "[%3ld] %-14s %-20s %-30.30s got through" CLR_RESET,
                         tick, events[0].source, attack_name(k), events[0].payload);
            }
            feed_add(&feed, line);
            bot_feedback(&bot, detected);
            changed = 1;
        }

        if (watch && changed) {
            draw_screen(tick, out, &bot, &feed);
            sleep_ms(delay_ms);
        }
    }

    out->ticks_run = tick - 1;
    out->ips_burned = bot.ips_burned;
    out->cracked = bot.cracked;
    out->ran_out_of_ips = bot.out_of_ips;

    g_last = *out;
    g_has_last = 1;
}

void sim_print_summary(const SimStats *s)
{
    printf(CLR_BOLD "SIMULATION RESULTS" CLR_RESET " (%ld ticks)\n", s->ticks_run);
    ui_separator();
    printf("%-22s %8s %9s %8s\n", "Attack type", "Actions", "Detected", "Rate");
    for (int k = 0; k < ATK_COUNT; k++) {
        int total = s->kind_total[k];
        double pct = total ? 100.0 * s->kind_detected[k] / total : 0.0;
        printf("%-22s %8d %9d %7.1f%%\n", attack_name((AttackKind)k), total, s->kind_detected[k], pct);
    }
    ui_separator();
    double rate = s->actions ? 100.0 * s->detected / s->actions : 0.0;
    printf("Detector score: %d   Attacker score: %d   Detection rate: %.1f%%\n",
           s->detected, s->missed, rate);
    printf("Normal events: %d   False alarms: %d   Attacker IPs burned: %d/%d\n",
           s->benign, s->false_alarms, s->ips_burned, BOT_IP_COUNT);
    if (s->ran_out_of_ips) {
        printf("The attacker ran out of IP addresses.\n");
    }
    ui_separator();

    if (s->cracked) {
        printf(CLR_RED CLR_BOLD "ATTACKER WINS: the admin password was cracked!" CLR_RESET "\n");
    } else if (s->detected > s->missed) {
        printf(CLR_GREEN CLR_BOLD "DETECTOR WINS: the system was defended." CLR_RESET "\n");
    } else if (s->detected < s->missed) {
        printf(CLR_RED CLR_BOLD "ATTACKER WINS: more attacks got through than were caught." CLR_RESET "\n");
    } else {
        printf(CLR_YELLOW CLR_BOLD "DRAW." CLR_RESET "\n");
    }
}

int sim_get_last(SimStats *out)
{
    if (g_has_last && out != NULL) {
        *out = g_last;
    }
    return g_has_last;
}

/* ------------------------------------------------------------------
 * Human attacker mode
 * ---------------------------------------------------------------- */

#define HUMAN_IPS 5
#define HUMAN_FLOOD 20

static void show_wordlist(void)
{
    printf("Leaked list of common passwords (the admin uses one of them):\n");
    for (int i = 0; i < COMMON_PASSWORD_COUNT; i++) {
        printf("  %-11s", COMMON_PASSWORDS[i]);
        if (i % 6 == 5) {
            printf("\n");
        }
    }
    printf("\n");
}

void sim_human_mode(void)
{
    static Detector det;
    detector_init(&det);
    srand((unsigned)time(NULL));

    const char *secret = COMMON_PASSWORDS[rand() % COMMON_PASSWORD_COUNT];
    long tick = 1;
    int ip_number = 1;
    int ips_left = HUMAN_IPS - 1;
    char ip[EV_SOURCE_LEN];
    int your_points = 0;
    int detector_points = 0;
    int cracked = 0;
    char message[200] = "Try to break in without being caught.";

    snprintf(ip, sizeof ip, "198.51.100.%d", ip_number);

    while (!cracked) {
        long blocked = detector_blocked_for(&det, ip, tick);

        ui_clear();
        printf(CLR_BOLD "YOU ARE THE ATTACKER" CLR_RESET "   tick %ld\n", tick);
        ui_separator();
        printf(CLR_BOLD "Your score: " CLR_RED "%d" CLR_RESET CLR_BOLD "   Detector score: " CLR_GREEN "%d" CLR_RESET "\n",
               your_points, detector_points);
        printf("Your IP: %s   %s   Spare IPs: %d\n", ip,
               blocked ? CLR_RED "BLOCKED" CLR_RESET : CLR_GREEN "not blocked" CLR_RESET, ips_left);
        if (blocked) {
            printf("Blocked for %ld more ticks.\n", blocked);
        }
        ui_separator();
        show_wordlist();
        ui_separator();
        printf("%s\n\n", message);
        printf("1. Guess the admin password\n");
        printf("2. Try to open the admin page\n");
        printf("3. Send your own request (try an injection)\n");
        printf("4. Flood the server (%d requests)\n", HUMAN_FLOOD);
        printf("5. Wait 10 ticks (slow down)\n");
        printf("6. Switch to a new IP address\n");
        printf("0. Give up\n");

        int choice;
        if (read_int("Your move: ", 0, 6, &choice) < 0 || choice == 0) {
            break;
        }

        Event e;
        Verdict v = V_ALLOW;
        char text[EV_PAYLOAD_LEN];
        int is_attack = 1;

        if (choice == 1) {
            printf("Password guess: ");
            fflush(stdout);
            if (read_line(text, sizeof text) < 0) {
                break;
            }
            int correct = strcmp(text, secret) == 0;
            event_make(&e, tick, ip, "admin", correct ? EV_LOGIN_OK : EV_LOGIN_FAIL, "password=***");
            v = detector_process(&det, &e);
            if (v == V_ALLOW && correct) {
                cracked = 1;
            }
        } else if (choice == 2) {
            event_make(&e, tick, ip, "attacker", EV_ACCESS_DENIED, "GET /admin/users");
            v = detector_process(&det, &e);
        } else if (choice == 3) {
            printf("Request text (for example q=1' OR '1'='1): ");
            fflush(stdout);
            if (read_line(text, sizeof text) < 0) {
                break;
            }
            event_make(&e, tick, ip, "attacker", EV_REQUEST, text);
            v = detector_process(&det, &e);
        } else if (choice == 4) {
            for (int i = 0; i < HUMAN_FLOOD; i++) {
                event_make(&e, tick, ip, "attacker", EV_REQUEST, "GET /");
                Verdict one = detector_process(&det, &e);
                if (v == V_ALLOW && one != V_ALLOW) {
                    v = one;
                }
            }
        } else if (choice == 5) {
            tick += 10;
            is_attack = 0;
            snprintf(message, sizeof message, "You waited 10 ticks.");
        } else if (choice == 6) {
            is_attack = 0;
            if (ips_left > 0) {
                ips_left--;
                ip_number++;
                snprintf(ip, sizeof ip, "198.51.100.%d", ip_number);
                snprintf(message, sizeof message, "You are now using %s.", ip);
            } else {
                snprintf(message, sizeof message, "You have no spare IP addresses left.");
            }
        }

        if (is_attack) {
            if (cracked) {
                your_points++;
            } else if (v == V_ALLOW) {
                your_points++;
                snprintf(message, sizeof message, CLR_RED "Not detected. You get a point." CLR_RESET);
            } else {
                detector_points++;
                snprintf(message, sizeof message,
                         CLR_GREEN "DETECTED (%s). The detector gets a point." CLR_RESET, verdict_name(v));
            }
        }
        tick++;

        if (detector_blocked_for(&det, ip, tick) > 0 && ips_left == 0 && !cracked) {
            snprintf(message, sizeof message, "Your last IP is blocked and you have no spare IPs.");
            break;
        }
    }

    ui_clear();
    printf(CLR_BOLD "GAME OVER" CLR_RESET "\n");
    ui_separator();
    printf("Your score: %d   Detector score: %d\n", your_points, detector_points);
    printf("%s\n", message);
    if (cracked) {
        printf(CLR_RED CLR_BOLD "You cracked the admin password (%s)! You win." CLR_RESET "\n", secret);
    } else if (detector_points >= your_points) {
        printf(CLR_GREEN CLR_BOLD "The detector wins. (The password was \"%s\".)" CLR_RESET "\n", secret);
    } else {
        printf(CLR_RED CLR_BOLD "You win on points. (The password was \"%s\".)" CLR_RESET "\n", secret);
    }
    log_event(LOG_INFO, NULL, "human attack game: player %d, detector %d, cracked=%d",
              your_points, detector_points, cracked);
}
