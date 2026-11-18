# Complexity analysis

Notation: U = number of users, L = password length, S = sources tracked by the detector
(at most 64), A = accounts tracked (at most 64), K = number of signatures (10),
n = length of a request, m = length of a signature (at most 13), W = window capacity (32),
T = attack types (4), P = injection payloads (8), B = flood burst (20).

## Part 1: accounts and access

| Operation | Function | Time | Why |
| --- | --- | --- | --- |
| Find a user | `userdb_find` | O(log U) | Binary search on the sorted array |
| Add a user | `userdb_add` | O(U) | O(log U) to find the spot, O(U) to shift the array with `memmove` |
| Grow the array | `ensure_capacity` | O(1) amortized | Capacity doubles, so copies add up to O(U) over U inserts |
| Load the database | `userdb_load` | O(U log U) | The file is saved sorted, so each insert lands at the end (no shifting) |
| Hash a password | `hash_password` | O(L) | One pass over salt + password, then 1000 rounds of constant work |
| Is this action allowed? | `access_allowed` | O(1) | One lookup in the role x feature table |
| Login | `auth_login` | O(log U + L) | Find the user, then hash |

The "is this action allowed?" check plays the role of "does this move complete a box?" in
Dots and Boxes: it runs after every action, so it must be fast. A table lookup is O(1).

## Part 2: the intrusion detector

| Operation | Function | Time | Space |
| --- | --- | --- | --- |
| Add an event to a sliding window | `window_add` | O(1) amortized | O(W) per window |
| Find a source / account | `get_source`, `get_account` | O(S), O(A) | O(S + A) |
| Build KMP tables | `prepare_signatures` | O(K m), done once | O(K m) |
| Signature check | `signature_match` | O(K (n + m)) | O(n) |
| Process one event | `detector_process` | O(S + A + K (n + m)) | - |

Sliding window: each timestamp is added once and removed once, so over E events the total
work is O(E), which is O(1) per event. Re-counting the whole history instead would be O(E) per event.

KMP vs. naive search: naive search compares the signature at every position, O(n m) per
signature. KMP never moves backwards in the text thanks to the failure table, so it is
O(n + m). With K signatures: O(K (n + m)) instead of O(K n m).

S and A are capped at 64, so in practice every detector step is bounded by a constant. With
many more sources, a hash table would make the lookup O(1) on average.

## Part 2: the attacker bot

| Operation | Function | Time |
| --- | --- | --- |
| Choose an attack type | `choose_kind` | O(T) |
| Choose an injection payload | `choose_payload` | O(P) |
| Produce one action | `bot_act` | O(1), or O(B) for a flood |
| Learn from the result | `bot_feedback` | O(T) |

The strategy is "epsilon-greedy": with probability 15% the bot explores a random attack type,
otherwise it picks the type with the best smoothed success rate (successes + 1) / (attempts + 2).
When it is caught it changes IP, doubles its delay (up to 8 ticks) to stay under the detector's
limits, and re-chooses. Each decision is O(T); a whole simulation of R ticks costs
O(R x (events per tick) x cost of detector_process).

## Part 3: server

Each command costs O(log U) for the database plus one detector step. All threads share one
lock per data structure, so commands from different clients that touch the same structure run
one after another (the critical sections are short).

## How to measure (optional, for the report)

Time the simulation with `time ./build/test_sentinel`, or write a small loop that calls
`kmp_find` and a naive search on texts of 1,000 to 100,000 characters and compare the times.
