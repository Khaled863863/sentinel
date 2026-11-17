#ifndef IDS_H
#define IDS_H

/*
 * Intrusion detection system (IDS).
 *
 * The detector looks at a stream of events (logins, requests, denied actions)
 * and raises an alert when it sees an attack. It uses:
 *   1. Sliding-window rate detection: "too many X from one source in T ticks"
 *      (brute force, floods, privilege escalation, suspicious input).
 *   2. A per-account window that catches attackers who switch IP addresses.
 *   3. Signature matching with the KMP string-search algorithm.
 *   4. A behavior check for requests full of unusual characters.
 * A source that triggers an alert is blocked for BLOCK_TICKS. When several
 * addresses from the same range (x.y.z.*) are blocked, the whole range is blocked.
 *
 * A "tick" is one time step. The simulation uses its own ticks; the live
 * program and the server use seconds.
 */

#define EV_SOURCE_LEN 24
#define EV_USER_LEN 24
#define EV_PAYLOAD_LEN 96

typedef enum {
    EV_LOGIN_FAIL,
    EV_LOGIN_OK,
    EV_ACCESS_DENIED,
    EV_ACCESS_OK,
    EV_REQUEST
} EventType;

typedef struct {
    long tick;
    char source[EV_SOURCE_LEN]; /* IP address or terminal name */
    char username[EV_USER_LEN];
    EventType type;
    char payload[EV_PAYLOAD_LEN]; /* request text, e.g. "GET /home" */
    int is_attack;                /* ground truth for statistics; the detector never reads it */
    int kind;                     /* attack kind (see attacker.h), -1 for normal traffic */
} Event;

typedef enum {
    V_ALLOW = 0,
    V_BRUTE_FORCE,       /* many failed logins from one source */
    V_DISTRIBUTED_BRUTE, /* many failed logins on one account from different sources */
    V_FLOOD,             /* too many requests in a short time (DoS) */
    V_PRIV_ESC,          /* repeated attempts to use forbidden features */
    V_SIGNATURE,         /* request matches a known attack pattern */
    V_ANOMALY,           /* several requests full of unusual characters */
    V_SUBNET,            /* too many attackers from the same address range */
    V_BLOCKED            /* source is already blocked */
} Verdict;

/* Thresholds: LIMIT events inside WINDOW ticks trigger an alert. */
#define BRUTE_LIMIT 4
#define BRUTE_WINDOW 20
#define ACCOUNT_LIMIT 6
#define ACCOUNT_WINDOW 60
#define FLOOD_LIMIT 15
#define FLOOD_WINDOW 5
#define PRIV_LIMIT 3
#define PRIV_WINDOW 30
#define ACCOUNT_DENIED_LIMIT 3
#define ACCOUNT_DENIED_WINDOW 60
#define ANOMALY_LIMIT 2
#define ANOMALY_WINDOW 30
#define BLOCK_TICKS 50
#define SUBNET_LIMIT 3 /* blocked IPs from one x.y.z.* range before the whole range is blocked */

#define WINDOW_CAP 32  /* must be larger than every LIMIT above */
#define MAX_TRACKED 64 /* sources / accounts remembered at the same time */
#define MAX_SUBNETS 16

/* Circular queue of event times (the sliding window). */
typedef struct {
    long times[WINDOW_CAP];
    int start;
    int count;
} TimeWindow;

typedef struct {
    char source[EV_SOURCE_LEN];
    TimeWindow fails;      /* failed logins */
    TimeWindow requests;   /* requests (EV_REQUEST) */
    TimeWindow denied;     /* access denied */
    TimeWindow suspicious; /* requests with unusual characters */
    long blocked_until;
    long last_seen;
} SourceState;

typedef struct {
    char username[EV_USER_LEN];
    TimeWindow fails;  /* failed logins on this account, from any source */
    TimeWindow denied; /* denied actions by this account, from any source */
    long last_seen;
} AccountState;

typedef struct {
    char prefix[EV_SOURCE_LEN]; /* e.g. "203.0.113." */
    long blocked_until;
} SubnetBlock;

typedef struct {
    SourceState sources[MAX_TRACKED];
    int source_count;
    AccountState accounts[MAX_TRACKED];
    int account_count;
    SubnetBlock subnets[MAX_SUBNETS];
    int subnet_count;
    long alerts;
} Detector;

void detector_init(Detector *d);

/* Looks at one event and returns V_ALLOW or the reason it raised an alert. */
Verdict detector_process(Detector *d, const Event *e);

/* Ticks left before source is unblocked (0 if it is not blocked). */
long detector_blocked_for(const Detector *d, const char *source, long tick);

const char *verdict_name(Verdict v);

/* Fills an event (is_attack = 0, kind = -1). */
void event_make(Event *e, long tick, const char *source, const char *user,
                EventType type, const char *payload);

/* --- Sliding window and KMP, exposed so they can be unit tested --- */

void window_init(TimeWindow *w);
/* Adds an event at time now, drops events older than span, returns how many are left. */
int window_add(TimeWindow *w, long now, long span);

/* Builds the KMP failure table for pattern p of length m. */
void kmp_build(const char *p, int m, int *fail);
/* Returns the first position of p in text, or -1. O(n + m). */
int kmp_find(const char *text, int n, const char *p, int m, const int *fail);

/* Returns 1 if the payload contains a known attack signature (case-insensitive),
 * and stores the signature number in *which. */
int signature_match(const char *payload, int *which);
const char *signature_text(int which);

#endif
