# What you two still need to do (the cherry on top)

The program, tests, Alpine scripts and docs are done. These steps are yours, and they are
worth 50% of the grade (report, presentation, GitHub, debugging strategy). Everything is due
**November 15**.

## 1. Understand every file (most important)

Both of you can be asked about any part in the oral exam. Suggested split for studying, then
explain your half to the other:

- **Khaled:** `auth.c`, `hash.c`, `access.c`, `ids.c`, `server.c`, `alpine/`
- **Rawad:** `main.c`, `input.c`, `logger.c`, `ui.c`, `attacker.c`, `simulation.c`, `client.c`, `net.c`

Questions to be ready for:
- Why do we store a salt and a hash instead of the password? Why does the salt matter?
- Why is `access_allowed` O(1) and `userdb_find` O(log n)? Why is adding a user O(n)?
- How does the sliding window work, and why is it O(1) per event?
- How does KMP avoid going back in the text? What is the failure table?
- How does the bot choose its next attack, and what does it do when it gets caught?
- How does the detector catch an attacker who keeps changing IPs?
- Why does the server need mutexes? What would go wrong without them?
- How does the VM log in automatically, and why is that a risk?
- Why do we show "wrong username or password" instead of "user not found"?

## 2. GitHub

1. Create a repository (for example `sentinel`) and add each other as collaborators.
2. Add the code in steps, not in one big commit: for example one commit per module as you
   study it (input, hashing, accounts, access control, log, UI, detector, bot, simulation,
   network). Each of you commits the modules you studied, with clear messages.
3. Keep committing your own changes from step 4 below.

## 3. Alpine VM

Follow `docs/ALPINE_SETUP.md`. Screenshots to take:
- The VM booting straight into Sentinel (no login prompt).
- `make clean`, `make`, `make test` on Alpine.
- (Bonus) the server on one VM and the client on the other.

## 4. Add your own touches

Pick a few, they make the project yours and give you real commits:
- Change the banner, colors or menu wording.
- Add your own attack signature in `src/ids.c` and a test for it.
- Tune a threshold (for example `BRUTE_LIMIT`) and explain the trade-off: lower catches more
  attacks but raises false alarms.
- Add a feature, for example "export the security report to a file" or "admin can view
  locked accounts only".

## 5. Debugging evidence

Follow `docs/DEBUGGING.md`: run the 4 GDB sessions and the Valgrind runs and screenshot them.
Use the table of real problems for the "debugging strategy" section of the report.

## 6. Report (suggested outline, about 6-10 pages)

1. Introduction: what Sentinel is and why we chose it (CMPS 243 elective).
2. How to build and run it; how the VM boots into it.
3. Part 1: accounts, hashing, lockout, roles, audit log (with screenshots).
4. Part 2: the detector rules, the bot strategy, the scoreboard (with screenshots).
5. Complexity analysis (from `docs/COMPLEXITY.md`).
6. Part 3: server, client, threads and mutexes (bonus).
7. Testing: unit tests, scripted session, network test.
8. Debugging strategy: GDB sessions, Valgrind results, problems found and fixed.
9. Team work: who did what, how you used GitHub.
10. Limitations: the hash and cipher are for learning; what real systems use instead.

## 7. Presentation (about 10 slides) and demo

Slides: title, the idea, architecture (modules), Part 1, Part 2 (bot vs detector), complexity,
Part 3, debugging, what we learned, demo.

Demo plan (5 minutes):
1. Boot the VM, show it opens Sentinel directly.
2. Create an admin, log in with a wrong password 3 times, show the lockout.
3. Log in as guest, try restricted features, show the detector logging you out.
4. Run "Watch the bot attack" and explain the scoreboard.
5. Admin: read the audit log.
6. (Bonus) Client on the second VM, then send `SEARCH q=1 UNION SELECT x` and get blocked.

## 8. Submit

- Everything on GitHub.
- Zip the project as `groupname.Sentinel.zip` and upload it to Moodle.
