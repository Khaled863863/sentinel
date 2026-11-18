#ifndef NET_H
#define NET_H

#include <stddef.h>

/*
 * Network helpers shared by the server and the client (Part 3, bonus).
 *
 * Each message is sent as a "frame": 2 bytes with the length, then the bytes
 * of the message, encrypted with a simple XOR cipher.
 * XOR with a fixed key is EDUCATIONAL ONLY: it hides the text from a casual
 * observer, but it is easy to break. Real systems use TLS.
 */

#define DEFAULT_PORT 5555
#define MAX_FRAME 1024

/* The shared key: $SENTINEL_KEY if set, otherwise a built-in default. */
const char *net_key(void);

/* XOR every byte with the key (doing it twice gives back the original). */
void xor_cipher(unsigned char *buf, size_t len, const char *key);

/* Writes / reads exactly len bytes (handles partial transfers). 0 ok, -1 error. */
int write_all(int fd, const void *buf, size_t len);
int read_all(int fd, void *buf, size_t len);

/* Encrypts and sends a text message. Returns 0 or -1. */
int send_frame(int fd, const char *msg, const char *key);

/* Receives and decrypts one message into buf ('\0'-terminated).
 * Returns its length, 0 if the other side closed the connection, -1 on error. */
int recv_frame(int fd, char *buf, size_t size, const char *key);

#endif
