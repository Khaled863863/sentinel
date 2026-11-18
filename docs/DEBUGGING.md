# Debugging guide (GDB and Valgrind)

The project requires debugging with GDB and Valgrind and a report on your strategy.
Run these sessions yourselves and take screenshots; they are part of the grade.

## Valgrind

```
make memcheck
```
Runs a full scripted session (register, login, wrong password, admin screens, simulation,
guest denied 3 times, attacker mode) under Memcheck. Expected: `ERROR SUMMARY: 0 errors`
and `in use at exit: 0 bytes`.

Unit tests under Valgrind:
```
valgrind --leak-check=full ./build/test_sentinel
```

Server, checking for data races between threads (Helgrind):
```
valgrind --tool=helgrind ./sentinel-server 5555
# in another terminal: run two clients, then Ctrl+C the server
```
Expected: `ERROR SUMMARY: 0 errors`.

## GDB sessions to show

Build is already with `-g -O0`, so GDB shows every variable.

**1. Watch the account lockout happen**
```
gdb ./sentinel
(gdb) break auth_login
(gdb) run
...log in with a wrong password...
(gdb) next             (repeat until after the hash comparison)
(gdb) print u->failed_attempts
(gdb) print *u
(gdb) backtrace
```

**2. Look inside the sliding window**
```
gdb ./build/test_sentinel
(gdb) break window_add
(gdb) run
(gdb) print *w
(gdb) finish           (shows the returned count)
```

**3. Watch the bot change its strategy**
```
gdb ./build/test_sentinel
(gdb) break bot_feedback if detected == 1
(gdb) run
(gdb) print b->kind
(gdb) print b->delay
(gdb) next ... (step to the end)
(gdb) print b->kind
(gdb) print b->delay      (it doubled)
```

**4. Threads in the server**
```
gdb ./sentinel-server
(gdb) run 5555
...connect two clients, then press Ctrl+C in gdb...
(gdb) info threads
(gdb) thread apply all backtrace
```

## Real problems we found while building it

These happened during development and are good material for the "debugging strategy" part
of the report. Reproduce them yourselves if you want screenshots.

| Problem | How it was found | Fix |
| --- | --- | --- |
| A guest who was kicked out by the detector blocked logins for everyone on the terminal for 50 seconds | Scripted test session went out of sync; the log showed the login was refused | The detector now uses a separate source per user session (`console:<name>`); logins use `console` |
| The server's flood rule triggered for normal users | Network test: two clients got "request flood" | Each command was counted twice (as a request and as a login/denied event). Now only requests count for floods |
| Data race on `g_stop` in the server | Helgrind: "Possible data race" between the signal handler and client threads | Client threads block SIGINT/SIGTERM and no longer read `g_stop`; shutdown wakes them by closing their sockets |
| Compiler warnings "output may be truncated" | `-Wall -Wextra` | Validate lengths first, then copy with `memcpy` |
| The attacker bot won most games | Ran 200 simulations and counted winners | Added per-account tracking for denied actions and blocking of whole address ranges |

## Optional exercise: plant a bug and catch it

Change `w->times[w->start] <= now - span` in `src/ids.c` to `<` (an off-by-one), run
`make test`, see which test fails, find the reason with GDB (break in `window_add`), then fix it.
This makes a good "before and after" for the report.
