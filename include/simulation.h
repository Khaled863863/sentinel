#ifndef SIMULATION_H
#define SIMULATION_H

#include "attacker.h"

/*
 * Attack simulation: the attacker bot against the intrusion detector.
 * Like the scores in Dots and Boxes:
 *   - the Detector gets a point for every attack action it catches,
 *   - the Attacker gets a point for every attack action that gets through.
 * The attacker wins at once if it cracks the admin password.
 */

#define SIM_TICKS 300

typedef struct {
    long ticks_run;
    int actions;      /* attack actions (a flood of 20 requests counts as 1 action) */
    int detected;     /* Detector points */
    int missed;       /* Attacker points */
    int benign;       /* normal events */
    int false_alarms; /* normal events the detector flagged by mistake */
    int ips_burned;
    int cracked;
    int ran_out_of_ips;
    int kind_total[ATK_COUNT];
    int kind_detected[ATK_COUNT];
} SimStats;

/* Runs one simulation. watch = 1 redraws the screen every tick (delay_ms per tick). */
void sim_run(int watch, int delay_ms, unsigned seed, SimStats *out);

void sim_print_summary(const SimStats *s);

/* 1 if a simulation was run since the program started (copies it into out). */
int sim_get_last(SimStats *out);

/* "You are the attacker": the player tries to break in while the detector watches. */
void sim_human_mode(void);

#endif
