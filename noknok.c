#include "yubikey.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

// TODO try what happens if illegal characters are fed to _yubikey_decode()
// TODO read configuration
// TODO persist counters on exit

size_t num_users;
struct userinfo {
    char *contextinfo; // TODO consider context (ignored for now)
    char *userid;
    char *yubi_public_id;
    uint32_t combined_counter;
    uint8_t aeskey[YUBIKEY_KEY_SIZE];
    uint8_t yubi_private_id[YUBIKEY_UID_SIZE];
} *users;

static void error_exit(const char *message, int use_perror)
{
    if (use_perror)
        perror(message);
    else
        fprintf(stderr, "%s\n", message);
    exit(1);
}

struct userinfo * get_userinfo_by_user_id(const char *user)
{
    size_t i;
    for (i = 0; i < num_users; i++) {
        if (!strcmp(users[i].userid, user))
            return &users[i];
    }
    return NULL;
}

struct userinfo * get_userinfo_by_public_id(const char *token)
{
    size_t i;
    size_t tokenlen = strlen(token);
    if (tokenlen <= 32)
        return NULL;
    for (i = 0; i < num_users; i++) {
        if (!strncmp(users[i].yubi_public_id, token, tokenlen - 32))
            return &users[i];
    }
    return NULL;
}

/* yubikey_decode() returns
 *   0 on success
 *  -1 when CRC does not match
 *  -2 when the token is too short
 */
static int yubikey_decode(const char *token, const uint8_t *aeskey,
                          uint8_t *private_id, uint16_t *counter,
                          bool *capslock, uint32_t *timestamp,
                          uint8_t *session_use, uint16_t *random)
{
    yubikey_token_st tok;
    if (strlen(token) > 32)
        token = token + (strlen(token) - 32);
    if (strlen(token) != 32)
        return -2;

    yubikey_parse((uint8_t *)token, aeskey, &tok);

    if (!yubikey_crc_ok_p((uint8_t *)&tok))
        return -1;

    if (private_id)
        memcpy(private_id, &tok.uid, YUBIKEY_UID_SIZE);
    if (counter)
        *counter = yubikey_counter(tok.ctr);
    if (capslock)
        *capslock = yubikey_capslock(tok.ctr) ? true : false;
    if (timestamp)
        *timestamp = tok.tstpl | tok.tstph << 16;
    if (session_use)
        *session_use = tok.use;
    if (random)
        *random = tok.rnd;
    return 0;
}

/* read_request() returns true on success or false on failure */
static bool read_request(int fd, char *buffer, size_t bufsize, char **context,
                         char **user, char **token)
{
    /* only consider whatever comes in with the first read() */
    size_t i, zero;
    int r = read(fd, buffer, bufsize);
    if (r == -1 || r == 0)
        return false;

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
        return true;

    *context = *user = *token = NULL;
    return false;
}

static void handle_connection(int fd)
{
    int ret;
    char buffer[1024];
    char *context, *userid, *token;
    struct userinfo *userinfo;
    uint8_t private_id[YUBIKEY_UID_SIZE];
    uint16_t counter, random;
    bool capslock;
    uint32_t timestamp, combined_counter;
    uint8_t session_use;

    if (!read_request(fd, buffer, sizeof(buffer), &context, &userid, &token))
        return;

    if (strlen(userid) == 0) {
        userinfo = get_userinfo_by_public_id(token);
    } else {
        userinfo = get_userinfo_by_user_id(userid);
    }

    if (!userinfo)
        return; /* can't identify user */

    ret = yubikey_decode(token, userinfo->aeskey, private_id, &counter,
                         &capslock, &timestamp, &session_use, &random);
    if (ret != 0)
        return;

    if (memcmp(private_id, userinfo->yubi_private_id, sizeof(private_id)))
        return;

    combined_counter = counter << 8 | session_use;
    if (combined_counter <= userinfo->combined_counter)
        return;

    userinfo->combined_counter = combined_counter;
    write(fd, userinfo->userid, strlen(userinfo->userid) + 1);
}

int main(int argc, char *argv[])
{
    char *path;
    int l;
    struct sockaddr_un local;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s socketpath\n", argv[0]);
        exit(1);
    }

    path = argv[1];
    l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l == -1)
        error_exit("Error creating socket", 1);

    unlink(path);

    // TODO use umask()?
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
