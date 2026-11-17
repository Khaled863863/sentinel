#include "ids.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------
 * Attack signatures (all lowercase; payloads are lowercased before matching)
 * ------------------------------------------------------------------- */

#define SIG_MAX_LEN 32

static const char *const SIGNATURES[] = {
    "' or '1'='1",   /* SQL injection */
    " or 1=1",       /* SQL injection */
    "union select",  /* SQL injection */
    "drop table",    /* SQL injection */
    "<script",       /* cross-site scripting */
    "../",           /* path traversal */
    "/etc/passwd",   /* reading system files */
    ";rm -rf",       /* command injection */
    "$(",            /* command injection */
    "%n",            /* format-string attack */
};

#define SIG_COUNT ((int)(sizeof SIGNATURES / sizeof SIGNATURES[0]))

static int g_sig_fail[SIG_COUNT][SIG_MAX_LEN];
static int g_sig_len[SIG_COUNT];
static int g_sig_ready = 0;

/* Characters that rarely appear in normal requests. */
static const char SUSPICIOUS_CHARS[] = "'\";<>%*`|$";

/* ---------------------------------------------------------------------
 * Sliding window: a circular queue of timestamps.
 * Each event is added once and removed once, so the cost per event
 * is O(1) amortized.
 * ------------------------------------------------------------------- */

void window_init(TimeWindow *w)
{
    w->start = 0;
    w->count = 0;
}

int window_add(TimeWindow *w, long now, long span)
{
    /* Drop events that are too old. */
    while (w->count > 0 && w->times[w->start] <= now - span) {
        w->start = (w->start + 1) % WINDOW_CAP;
        w->count--;
    }
    /* Queue full: forget the oldest one (the limits are always below WINDOW_CAP). */
    if (w->count == WINDOW_CAP) {
        w->start = (w->start + 1) % WINDOW_CAP;
        w->count--;
    }
    w->times[(w->start + w->count) % WINDOW_CAP] = now;
    w->count++;
    return w->count;
}

/* ---------------------------------------------------------------------
 * KMP string search: O(m) to prepare a pattern, O(n) to scan a text.
 * ------------------------------------------------------------------- */

void kmp_build(const char *p, int m, int *fail)
{
    if (m <= 0) {
        return;
    }
    fail[0] = 0;
    int k = 0;
    for (int i = 1; i < m; i++) {
        while (k > 0 && p[i] != p[k]) {
            k = fail[k - 1];
        }
        if (p[i] == p[k]) {
            k++;
        }
        fail[i] = k;
    }
}

int kmp_find(const char *text, int n, const char *p, int m, const int *fail)
{
    if (m == 0) {
        return 0;
    }
    int k = 0;
    for (int i = 0; i < n; i++) {
        while (k > 0 && text[i] != p[k]) {
            k = fail[k - 1];
        }
        if (text[i] == p[k]) {
            k++;
        }
        if (k == m) {
            return i - m + 1;
        }
    }
    return -1;
}

static void prepare_signatures(void)
{
    if (g_sig_ready) {
        return;
    }
    for (int s = 0; s < SIG_COUNT; s++) {
        g_sig_len[s] = (int)strlen(SIGNATURES[s]);
        kmp_build(SIGNATURES[s], g_sig_len[s], g_sig_fail[s]);
    }
    g_sig_ready = 1;
}

int signature_match(const char *payload, int *which)
{
    char lower[EV_PAYLOAD_LEN];
    int n = 0;

    prepare_signatures();
    for (; payload[n] != '\0' && n < EV_PAYLOAD_LEN - 1; n++) {
        lower[n] = (char)tolower((unsigned char)payload[n]);
    }
    lower[n] = '\0';

    for (int s = 0; s < SIG_COUNT; s++) {
        if (kmp_find(lower, n, SIGNATURES[s], g_sig_len[s], g_sig_fail[s]) >= 0) {
            if (which != NULL) {
                *which = s;
            }
            return 1;
        }
    }
    return 0;
}

const char *signature_text(int which)
{
    if (which < 0 || which >= SIG_COUNT) {
        return "?";
    }
    return SIGNATURES[which];
}

/* A request is "suspicious" if it has 2 or more unusual characters. */
static int is_suspicious(const char *payload)
{
    int score = 0;
    for (; *payload != '\0'; payload++) {
        if (strchr(SUSPICIOUS_CHARS, *payload) != NULL) {
            score++;
        }
    }
    return score >= 2;
}

/* ---------------------------------------------------------------------
 * Detector
 * ------------------------------------------------------------------- */

void detector_init(Detector *d)
{
    memset(d, 0, sizeof *d);
    prepare_signatures();
}

/* Finds the state of a source, or creates it. When the table is full,
 * the source not seen for the longest time is replaced. O(MAX_TRACKED). */
static SourceState *get_source(Detector *d, const char *source, long tick)
{
    int oldest = 0;
    for (int i = 0; i < d->source_count; i++) {
        if (strcmp(d->sources[i].source, source) == 0) {
            d->sources[i].last_seen = tick;
            return &d->sources[i];
        }
        if (d->sources[i].last_seen < d->sources[oldest].last_seen) {
            oldest = i;
        }
    }

    int slot = (d->source_count < MAX_TRACKED) ? d->source_count++ : oldest;
    SourceState *s = &d->sources[slot];
    memset(s, 0, sizeof *s);
    snprintf(s->source, sizeof s->source, "%s", source);
    s->last_seen = tick;
    return s;
}

static AccountState *get_account(Detector *d, const char *username, long tick)
{
    int oldest = 0;
    for (int i = 0; i < d->account_count; i++) {
        if (strcmp(d->accounts[i].username, username) == 0) {
            d->accounts[i].last_seen = tick;
            return &d->accounts[i];
        }
        if (d->accounts[i].last_seen < d->accounts[oldest].last_seen) {
            oldest = i;
        }
    }

    int slot = (d->account_count < MAX_TRACKED) ? d->account_count++ : oldest;
    AccountState *a = &d->accounts[slot];
    memset(a, 0, sizeof *a);
    snprintf(a->username, sizeof a->username, "%s", username);
    a->last_seen = tick;
    return a;
}

/* Writes the "x.y.z." part of an IPv4 address into out. Returns 0 if source has no dot. */
static int subnet_prefix(const char *source, char *out, size_t size)
{
    const char *last_dot = strrchr(source, '.');
    if (last_dot == NULL) {
        return 0;
    }
    size_t len = (size_t)(last_dot - source) + 1;
    if (len >= size) {
        return 0;
    }
    memcpy(out, source, len);
    out[len] = '\0';
    return 1;
}

static int subnet_blocked(const Detector *d, const char *source, long tick)
{
    char prefix[EV_SOURCE_LEN];
    if (!subnet_prefix(source, prefix, sizeof prefix)) {
        return 0;
    }
    for (int i = 0; i < d->subnet_count; i++) {
        if (d->subnets[i].blocked_until > tick && strcmp(d->subnets[i].prefix, prefix) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Called after a source is blocked: if SUBNET_LIMIT sources from its range
 * are blocked at the same time, block the whole range. O(MAX_TRACKED). */
static int maybe_block_subnet(Detector *d, const char *source, long tick)
{
    char prefix[EV_SOURCE_LEN], other[EV_SOURCE_LEN];
    if (!subnet_prefix(source, prefix, sizeof prefix)) {
        return 0;
    }
    int blocked = 0;
    for (int i = 0; i < d->source_count; i++) {
        if (d->sources[i].blocked_until > tick
            && subnet_prefix(d->sources[i].source, other, sizeof other)
            && strcmp(other, prefix) == 0) {
            blocked++;
        }
    }
    if (blocked < SUBNET_LIMIT) {
        return 0;
    }

    int slot = -1;
    for (int i = 0; i < d->subnet_count; i++) {
        if (strcmp(d->subnets[i].prefix, prefix) == 0 || d->subnets[i].blocked_until <= tick) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (d->subnet_count >= MAX_SUBNETS) {
            return 0;
        }
        slot = d->subnet_count++;
    }
    snprintf(d->subnets[slot].prefix, sizeof d->subnets[slot].prefix, "%s", prefix);
    d->subnets[slot].blocked_until = tick + 2 * BLOCK_TICKS;
    return 1;
}

Verdict detector_process(Detector *d, const Event *e)
{
    SourceState *s = get_source(d, e->source, e->tick);
    if (s->blocked_until > e->tick) {
        return V_BLOCKED;
    }
    if (subnet_blocked(d, e->source, e->tick)) {
        s->blocked_until = e->tick + BLOCK_TICKS;
        d->alerts++;
        return V_SUBNET;
    }

    Verdict v = V_ALLOW;

    /* 1. Known attack patterns. */
    if (e->payload[0] != '\0' && signature_match(e->payload, NULL)) {
        v = V_SIGNATURE;
    }

    /* 2. Too many requests from one source (flood / denial of service). */
    if (e->type == EV_REQUEST) {
        int recent = window_add(&s->requests, e->tick, FLOOD_WINDOW);
        if (v == V_ALLOW && recent >= FLOOD_LIMIT) {
            v = V_FLOOD;
        }
    }

    /* 3. Failed logins: per source and per account. */
    if (e->type == EV_LOGIN_FAIL) {
        int from_source = window_add(&s->fails, e->tick, BRUTE_WINDOW);
        AccountState *a = get_account(d, e->username, e->tick);
        int on_account = window_add(&a->fails, e->tick, ACCOUNT_WINDOW);
        if (v == V_ALLOW && from_source >= BRUTE_LIMIT) {
            v = V_BRUTE_FORCE;
        } else if (v == V_ALLOW && on_account >= ACCOUNT_LIMIT) {
            v = V_DISTRIBUTED_BRUTE;
        }
    }

    /* 4. Repeated attempts to use forbidden features. */
    if (e->type == EV_ACCESS_DENIED) {
        int denied = window_add(&s->denied, e->tick, PRIV_WINDOW);
        AccountState *a = get_account(d, e->username, e->tick);
        int by_account = window_add(&a->denied, e->tick, ACCOUNT_DENIED_WINDOW);
        if (v == V_ALLOW && (denied >= PRIV_LIMIT || by_account >= ACCOUNT_DENIED_LIMIT)) {
            v = V_PRIV_ESC;
        }
    }

    /* 5. Behavior-based check: catches attacks that hide from the signatures. */
    if (e->payload[0] != '\0' && is_suspicious(e->payload)) {
        int odd = window_add(&s->suspicious, e->tick, ANOMALY_WINDOW);
        if (v == V_ALLOW && odd >= ANOMALY_LIMIT) {
            v = V_ANOMALY;
        }
    }

    if (v != V_ALLOW) {
        s->blocked_until = e->tick + BLOCK_TICKS;
        d->alerts++;
        maybe_block_subnet(d, e->source, e->tick);
    }
    return v;
}

long detector_blocked_for(const Detector *d, const char *source, long tick)
{
    char prefix[EV_SOURCE_LEN];
    if (subnet_prefix(source, prefix, sizeof prefix)) {
        for (int i = 0; i < d->subnet_count; i++) {
            if (strcmp(d->subnets[i].prefix, prefix) == 0 && d->subnets[i].blocked_until > tick) {
                return d->subnets[i].blocked_until - tick;
            }
        }
    }
    for (int i = 0; i < d->source_count; i++) {
        if (strcmp(d->sources[i].source, source) == 0) {
            long left = d->sources[i].blocked_until - tick;
            return left > 0 ? left : 0;
        }
    }
    return 0;
}

const char *verdict_name(Verdict v)
{
    switch (v) {
    case V_ALLOW:             return "allowed";
    case V_BRUTE_FORCE:       return "brute force";
    case V_DISTRIBUTED_BRUTE: return "brute force from many IPs";
    case V_FLOOD:             return "request flood";
    case V_PRIV_ESC:          return "privilege escalation";
    case V_SIGNATURE:         return "attack signature";
    case V_ANOMALY:           return "suspicious input";
    case V_SUBNET:            return "blocked address range";
    case V_BLOCKED:           return "blocked source";
    }
    return "?";
}

void event_make(Event *e, long tick, const char *source, const char *user,
                EventType type, const char *payload)
{
    memset(e, 0, sizeof *e);
    e->tick = tick;
    snprintf(e->source, sizeof e->source, "%s", source != NULL ? source : "?");
    snprintf(e->username, sizeof e->username, "%s", user != NULL ? user : "-");
    e->type = type;
    snprintf(e->payload, sizeof e->payload, "%s", payload != NULL ? payload : "");
    e->is_attack = 0;
    e->kind = -1;
}
