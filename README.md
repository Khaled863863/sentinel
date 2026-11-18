# Sentinel

A console host security system written in C, built for CMPS 241 (Systems Programming) by
Khaled Rabah and Rawad Akil. It boots directly on an Alpine Linux VM.

| Part | What it does |
| --- | --- |
| 1 | Accounts with salted password hashing, lockout after 3 wrong passwords, 3 roles (admin, user, guest), an access table redrawn after every action, and an audit log. |
| 2 | Attack simulation: an adaptive attacker bot against our intrusion detector, with a live scoreboard. You can also play the attacker yourself. |
| 3 (bonus) | A multithreaded server and a client for two VMs, with XOR-encrypted messages and mutexes on shared data. |

## Build and run

```
make            # builds sentinel, sentinel-server, sentinel-client
make run        # runs sentinel with its data in ./data
make test       # 58 unit tests
make memcheck   # scripted session under Valgrind (must say 0 errors)
make clean
```

The first account you create becomes the administrator.

Network version (Part 3):

```
./sentinel-server 5555                  # on the server VM
./sentinel-client <server-ip> 5555      # on the client VM
sh tests/network_test.sh                # automatic test on one machine
```

## Files

| File | What it does |
| --- | --- |
| `src/main.c` | Menus, login, registration, the logged-in session (access table), admin screens |
| `src/input.c` | Safe input: bounded reads, number parsing, hidden passwords, username/password rules |
| `src/hash.c` | FNV-1a hash with salt and 1000 rounds, random salts, constant-time compare |
| `src/auth.c` | User database (sorted dynamic array, binary search), load/save, login and lockout |
| `src/access.c` | The role x feature permission table |
| `src/logger.c` | Thread-safe audit log, protected against fake log lines |
| `src/ui.c` | Colors, banner, drawing the access table |
| `src/ids.c` | The intrusion detector: sliding windows, KMP signature search, IP and range blocking |
| `src/attacker.c` | The attacker bot (epsilon-greedy strategy) and normal user traffic |
| `src/simulation.c` | Runs the bot against the detector, scoreboard, "you are the attacker" mode |
| `src/net.c` | Message framing and the XOR cipher |
| `src/server.c` | Multithreaded server (one thread per client, mutexes) |
| `src/client.c` | Network client |
| `tests/test_sentinel.c` | Unit tests |
| `tests/demo_input.txt` | Scripted session used by `make memcheck` |
| `tests/network_test.sh` | Server + two clients test |
| `alpine/` | Scripts that make the VM boot straight into Sentinel |
| `docs/` | Setup guide, complexity analysis, debugging guide, your task list |

## Security notes

The hash (FNV-1a) and the XOR cipher are simple versions for learning. Real systems use
bcrypt or Argon2 for passwords and TLS for network traffic. All attacks in the simulation are
fake events created by our own program.
