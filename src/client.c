/*
 * Sentinel client (Part 3, bonus).
 *
 * Usage: ./sentinel-client [server-address] [port]
 * Example (from the second VM): ./sentinel-client 192.168.56.10 5555
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "input.h"
#include "net.h"

static int connect_to(const char *host, const char *port)
{
    struct addrinfo hints, *list = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0) {
        fprintf(stderr, "Cannot find %s: %s\n", host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *a = list; a != NULL; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);
    return fd;
}

int main(int argc, char *argv[])
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    char default_port[8];
    snprintf(default_port, sizeof default_port, "%d", DEFAULT_PORT);
    const char *port = argc > 2 ? argv[2] : default_port;

    int fd = connect_to(host, port);
    if (fd < 0) {
        fprintf(stderr, "Could not connect to %s:%s\n", host, port);
        return 1;
    }

    const char *key = net_key();
    char line[MAX_FRAME];
    char reply[MAX_FRAME + 1];

    if (recv_frame(fd, reply, sizeof reply, key) > 0) {
        printf("%s\n", reply);
    }

    for (;;) {
        printf("sentinel> ");
        fflush(stdout);

        int r = read_line(line, sizeof line);
        if (r < 0) {
            send_frame(fd, "QUIT", key);
            (void)recv_frame(fd, reply, sizeof reply, key);
            break;
        }
        if (r == 0) {
            printf("That line is too long.\n");
            continue;
        }
        if (line[0] == '\0') {
            continue;
        }

        if (send_frame(fd, line, key) != 0) {
            printf("Connection lost.\n");
            break;
        }
        int n = recv_frame(fd, reply, sizeof reply, key);
        if (n <= 0) {
            printf("The server closed the connection.\n");
            break;
        }
        printf("%s\n", reply);

        if (strcmp(line, "QUIT") == 0 || strncmp(reply, "BLOCKED", 7) == 0) {
            break;
        }
    }

    close(fd);
    return 0;
}
