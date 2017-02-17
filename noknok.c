#include "yubikey.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void error_exit(const char *message, int use_perror)
{
    if (use_perror)
        perror(message);
    else
        fprintf(stderr, "%s\n", message);
    exit(1);
}

static void yubikey_decode(char *token, char *aeskey) {
    yubikey_token_st tok;
    uint8_t key[YUBIKEY_KEY_SIZE];
    if (strlen(aeskey) != 32)
        return;
    if (strlen(token) > 32)
        token = token + (strlen(token) - 32);
    if (strlen(token) != 32)
        return;
    yubikey_hex_decode((char *)key, aeskey, YUBIKEY_KEY_SIZE);
    yubikey_parse((uint8_t *)token, key, &tok);

    // TODO return using out pointers (data types?)
    char buf[2 * YUBIKEY_UID_SIZE + 1];
    int counter = yubikey_counter(tok.ctr);
    int capslock = yubikey_capslock(tok.ctr);
    long timestamp = tok.tstpl | tok.tstph << 16;
    int session_use = tok.use;
    int random = tok.rnd;
    int crc = tok.crc;
    yubikey_modhex_encode(buf, (char *)tok.uid, YUBIKEY_UID_SIZE);
    // TODO if (!yubikey_crc_ok_p((uint8_t *)&tok));
}

/* read_request() returns 1 on success or 0 on failure */
static int read_request(int fd, char **context, char **user, char **token)
{
    /* only consider whatever comes in with the first read() */
    char buffer[1024];
    size_t i, zero;
    int r = read(fd, buffer, sizeof(buffer));
    if (r == -1 || r == 0)
        return;

    *context = NULL;
    *user = NULL;
    *token = NULL;
    for (i = 0; i < r; i++) {
        if (buffer[i] == '!') {
            buffer[i] = 0;
            if (!*context) {
                *context = buffer;
                zero = i;
            } else if (!*user) {
                *user = &buffer[zero + 1];
                zero = i;
            } else {
                *token = &buffer[zero + 1];
                break;
            }
        }
    }

    if (*context && *user && *token)
        return 1;

    *context = *user = *token = NULL;
    return 0;
}

static void handle_connection(int fd)
{
    char *context, *user, *token;
    if (!read_request(fd, &context, &user, &token))
        return;
    // TODO read AES key from database (hex string)
    yubikey_decode(token, "");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s socketpath\n", argv[0]);
        exit(1);
    }

    char *path = argv[1];
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l == -1)
        error_exit("Error creating socket", 1);

    unlink(path);

    // TODO use umask()?
    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, path, sizeof(local.sun_path) - 1);
    if (bind(l, (struct sockaddr *)&local, sizeof(struct sockaddr_un)) == -1)
        error_exit("Error binding socket", 1);

    if (listen(l, 3) == -1)
        error_exit("Error listening to socket", 1);

    while (1) {
        int c = accept(l, NULL, NULL);
        if (c == -1)
            error_exit("Error accepting connection", 1);
        handle_connection(c);
        close(c);
    }
}
