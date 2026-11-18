#include "net.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *net_key(void)
{
    const char *key = getenv("SENTINEL_KEY");
    if (key == NULL || key[0] == '\0') {
        key = "cmps241-sentinel-key";
    }
    return key;
}

void xor_cipher(unsigned char *buf, size_t len, const char *key)
{
    size_t key_len = strlen(key);
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (unsigned char)key[i % key_len];
    }
}

int write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int read_all(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1; /* connection closed in the middle of a message */
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int send_frame(int fd, const char *msg, const char *key)
{
    size_t len = strlen(msg);
    if (len > MAX_FRAME) {
        len = MAX_FRAME;
    }

    unsigned char frame[2 + MAX_FRAME];
    frame[0] = (unsigned char)(len >> 8);
    frame[1] = (unsigned char)(len & 0xff);
    memcpy(frame + 2, msg, len);
    xor_cipher(frame + 2, len, key);

    return write_all(fd, frame, 2 + len);
}

int recv_frame(int fd, char *buf, size_t size, const char *key)
{
    unsigned char header[2];
    ssize_t n;

    /* Read the first byte separately so a clean close returns 0. */
    do {
        n = read(fd, header, 1);
    } while (n < 0 && errno == EINTR);
    if (n == 0) {
        return 0;
    }
    if (n < 0 || read_all(fd, header + 1, 1) != 0) {
        return -1;
    }

    size_t len = ((size_t)header[0] << 8) | header[1];
    if (len > MAX_FRAME || len + 1 > size) {
        return -1; /* refuse messages that would not fit */
    }
    if (len > 0 && read_all(fd, buf, len) != 0) {
        return -1;
    }
    xor_cipher((unsigned char *)buf, len, key);
    buf[len] = '\0';
    return (int)len;
}
