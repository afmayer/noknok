#include "yubikey.h"
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

struct contextinfo {
    char *context;
    char *username;
};

size_t num_users;
struct userinfo {
    size_t num_context;
    struct contextinfo *context;
    char *yubi_public_id;
    uint32_t combined_counter;
    uint8_t aeskey[YUBIKEY_KEY_SIZE];
    uint8_t yubi_private_id[YUBIKEY_UID_SIZE];
} *users;

static uint8_t zeroid[YUBIKEY_UID_SIZE];
static uint8_t zerokey[YUBIKEY_KEY_SIZE];

static bool debug_requests;
const char *counterpath = "/var/lib/noknok/counters";

static void error_exit(const char *message, int use_perror)
{
    if (use_perror)
        perror(message);
    else
        fprintf(stderr, "%s\n", message);
    exit(1);
}

static struct userinfo * get_userinfo_by_username(char *context, char *username)
{
    size_t i, j;
    for (i = 0; i < num_users; i++) {
        for (j = 0; j < users[i].num_context; j++) {
            if (!strcmp(users[i].context[j].context, context)) {
                if (!strcmp(users[i].context[j].username, username))
                    return &users[i];
            }
        }
    }
    return NULL;
}

static struct userinfo * get_userinfo_by_public_id(char *context,
                                                   const char *token,
                                                   char **out_username)
{
    size_t i, j;
    size_t tokenlen = strlen(token);
    if (tokenlen <= 32)
        return NULL;
    for (i = 0; i < num_users; i++) {
        if (!users[i].yubi_public_id)
            continue;
        if (!strncmp(users[i].yubi_public_id, token, tokenlen - 32)) {
            for (j = 0; j < users[i].num_context; j++) {
                if (!strcmp(users[i].context[j].context, context)) {
                    *out_username = users[i].context[j].username;
                    return &users[i];
                }
            }
        }
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
    if (strlen(token) != 32) {
        if (debug_requests)
            fprintf(stderr, "   RESULT: REJECTED (token too short)\n\n");
        return -2;
    }

    yubikey_parse((uint8_t *)token, aeskey, &tok);

    if (!yubikey_crc_ok_p((uint8_t *)&tok)) {
        if (debug_requests)
            fprintf(stderr, "   RESULT: REJECTED (CRC mismatch)\n\n");
        return -1;
    }

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
    for (i = 0; i < (size_t)r; i++) {
        if (buffer[i] == '\0') {
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
    bool bret;
    int ret;
    char buffer[1024];
    char *context, *userid, *token;
    struct userinfo *userinfo;
    uint8_t private_id[YUBIKEY_UID_SIZE];
    uint16_t counter, random;
    bool capslock;
    uint32_t timestamp, combined_counter;
    uint8_t session_use;

    bret = read_request(fd, buffer, sizeof(buffer), &context, &userid, &token);

    if (debug_requests) {
        if (bret)
            fprintf(stderr, "New incoming request\n"
                            "  context: %s\n"
                            "   userid: %s\n"
                            "    token: %s\n", context, userid, token);
        else
            fprintf(stderr, "New incoming request with INVALID FORMAT\n\n");
    }

    if (!bret)
        return;

    if (strlen(userid) == 0)
        userinfo = get_userinfo_by_public_id(context, token, &userid);
    else
        userinfo = get_userinfo_by_username(context, userid);

    if (!userinfo) {
        /* can't identify user */
        if (debug_requests)
            fprintf(stderr, "   RESULT: REJECTED (can't identify user)\n\n");
        return;
    }

    ret = yubikey_decode(token, userinfo->aeskey, private_id, &counter,
                         &capslock, &timestamp, &session_use, &random);
    if (ret != 0)
        return;

    if (memcmp(private_id, userinfo->yubi_private_id, YUBIKEY_UID_SIZE)) {
        if (debug_requests)
            fprintf(stderr, "   RESULT: REJECTED (ID does not match)\n\n");
        return;
    }

    combined_counter = counter << 8 | session_use;
    if (combined_counter <= userinfo->combined_counter) {
        if (debug_requests)
            fprintf(stderr, "   RESULT: REJECTED (old counter value)\n\n");
        return;
    }

    if (debug_requests)
        fprintf(stderr, "   RESULT: APPROVED (user \"%s\")\n\n", userid);

    userinfo->combined_counter = combined_counter;
    ret = write(fd, userid, strlen(userid) + 1);
}

static bool add_userinfo_if_complete(uint8_t *private_id, uint8_t *aeskey,
                                     char *public_id, size_t num_context,
                                     struct contextinfo *context)
{
    /* private ID and AES key are mandatory */
    if (!memcmp(zeroid, private_id, YUBIKEY_UID_SIZE))
        return false;
    if (!memcmp(zerokey, aeskey, YUBIKEY_KEY_SIZE))
        return false;
    users = realloc(users, (num_users + 1) * sizeof(*users));
    if (!users)
        error_exit("Out of memory", 0);

    users[num_users].num_context = num_context;
    users[num_users].context = context;
    users[num_users].combined_counter = 0; // TODO read from other config
    memcpy(users[num_users].aeskey, aeskey, YUBIKEY_KEY_SIZE);
    memcpy(users[num_users].yubi_private_id, private_id, YUBIKEY_UID_SIZE);
    users[num_users].yubi_public_id = public_id;
    num_users++;
    return true;
}

static void config_error_exit(size_t linenumber)
{
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "Error in configuration file (line %zu)",
             linenumber);
    error_exit(buffer, 0);
}

static void read_config(const char *configpath)
{
    int fd;
    struct stat stat;
    FILE *stream;
    ssize_t line_length;
    char *linebuf = NULL;
    size_t linebufsize;
    size_t linenum = 0;

    uint8_t aeskey[YUBIKEY_KEY_SIZE] = {0};
    uint8_t private_id[YUBIKEY_UID_SIZE] = {0};
    char *public_id = NULL;
    size_t num_context = 0;
    struct contextinfo *context = NULL;
    char *temp_context = NULL;
    char *temp_contextuser = NULL;

    fd = open(configpath, O_RDONLY);
    if (fd == -1)
        error_exit("Error opening configuration file", 1);
    if (fstat(fd, &stat) == -1)
        error_exit("Error calling fstat() on configuration file", 1);
    if (stat.st_mode & (S_IROTH | S_IWOTH))
        error_exit("Won't accept a world-readable or world-writable "
                   "configuration file", 0);
    stream = fdopen(fd, "r");
    if (!stream)
        error_exit("Error opening configuration file stream", 1);

    while ((line_length = getline(&linebuf, &linebufsize, stream)) != -1) {
        linenum++;
        if (linebuf[line_length - 1] == '\n') {
            linebuf[line_length - 1] = '\0';
            line_length--;
        }
        if (line_length == 0) {
            /* empty line - previous userinfo is complete */
            if (!add_userinfo_if_complete(private_id, aeskey, public_id,
                                          num_context, context))
                config_error_exit(linenum);
            memset(private_id, 0, YUBIKEY_UID_SIZE);
            memset(aeskey, 0, YUBIKEY_KEY_SIZE);
            public_id = NULL;
            num_context = 0;
            context = NULL;
        } else if (!strncmp(linebuf, "private_id ", 11)) {
            if (memcmp(zeroid, private_id, YUBIKEY_UID_SIZE))
                config_error_exit(linenum); /* id already set */
            if (line_length != 23)
                config_error_exit(linenum); /* ID length incorrect */
            yubikey_hex_decode((char *)private_id, linebuf + 11,
                               YUBIKEY_UID_SIZE);
        } else if (!strncmp(linebuf, "aeskey ", 7)) {
            if (memcmp(zerokey, aeskey, YUBIKEY_KEY_SIZE))
                config_error_exit(linenum); /* key already set */
            if (line_length != 39)
                config_error_exit(linenum); /* AES key length incorrect */
            yubikey_hex_decode((char *)aeskey, linebuf + 7, YUBIKEY_KEY_SIZE);
        } else if (!strncmp(linebuf, "public_id ", 10)) {
            if (public_id)
                config_error_exit(linenum); /* public ID already set */
            public_id = strdup(linebuf + 10);
        } else if (!strncmp(linebuf, "context ", 8)) {
            if (temp_context)
                config_error_exit(linenum);
            temp_context = strdup(linebuf + 8);
        } else if (!strncmp(linebuf, "contextuser ", 12)) {
            if (temp_contextuser)
                config_error_exit(linenum);
            temp_contextuser = strdup(linebuf + 12);
        }

        if (temp_context && temp_contextuser) {
            context = realloc(context, (num_context + 1) * sizeof(*context));
            if (!context)
                error_exit("Out of memory", 0);
            context[num_context].context = temp_context;
            context[num_context].username = temp_contextuser;
            num_context++;
            temp_context = NULL;
            temp_contextuser = NULL;
        }
    }

    /* add the last user in the file */
    if (!add_userinfo_if_complete(private_id, aeskey, public_id, num_context,
                                  context))
        config_error_exit(linenum);
    free(linebuf);
}

static void read_counters(void)
{
    // TODO implement read_counters()
}

static void persist_counters(void)
{
    /* this function must remain signal-safe */
    // TODO implement persist_counters()
}

static void signalhandler(int signum)
{
    persist_counters();
    _exit(0);
}

static void usage_exit(const char *argv0)
{
    fprintf(stderr, "Usage: %s [options] socketpath\n", argv0);
    exit(1);
}

#define argv_is(x) (strcmp(*argv, x) == 0)
#define assert_and_assign_next_argv_to(x) \
    do { \
        if (argc > 1) { \
            argv++; argc--; \
            (x) = *argv; \
        } else { \
            fprintf(stderr, "Missing argument for option '%s'\n", *argv); \
            exit(1); \
        } \
    } while (0)
int main(int argc, char *argv[])
{
    const char *argv0 = *argv;
    char *socketpath = NULL;
    char *configpath = "/etc/noknok.conf";
    struct sigaction sa;
    int l, rc;
    struct sockaddr_un local;
    mode_t oldmask;

    argv++; argc--;
    while (argc > 0) {
        if (argv_is("-c") || argv_is("--config")) {
            assert_and_assign_next_argv_to(configpath);
        } else if (argv_is("--counters")) {
            assert_and_assign_next_argv_to(counterpath);
        } else if (argv_is("--debug-requests")) {
            debug_requests = true;
        } else if (*argv[0] == '-') {
            fprintf(stderr, "Unknown option '%s'\n", *argv);
            exit(1);
        } else {
            if (socketpath)
                usage_exit(argv0);
            socketpath = *argv;
        }
        argv++; argc--;
    }

    if (!socketpath)
        usage_exit(argv0);

    read_config(configpath);
    read_counters();

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signalhandler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL) == -1 ||
            sigaction(SIGINT, &sa, NULL) == -1 ||
            sigaction(SIGPIPE, &sa, NULL) == -1 ||
            sigaction(SIGTERM, &sa, NULL) == -1 ||
            sigaction(SIGUSR1, &sa, NULL) == -1 ||
            sigaction(SIGUSR2, &sa, NULL) == -1)
        error_exit("Error installing signal handler", 1);

    l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l == -1)
        error_exit("Error creating socket", 1);

    unlink(socketpath);

    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, socketpath, sizeof(local.sun_path) - 1);
    oldmask = umask(0);
    rc = bind(l, (struct sockaddr *)&local, sizeof(struct sockaddr_un));
    umask(oldmask);
    if (rc == -1)
        error_exit("Error binding socket", 1);

    if (listen(l, 3) == -1)
        error_exit("Error listening to socket", 1);

    if (atexit(persist_counters) != 0)
        error_exit("Error installing exit handler", 0);

    while (1) {
        int c = accept(l, NULL, NULL);
        if (c == -1)
            error_exit("Error accepting connection", 1);
        handle_connection(c);
        close(c);
    }
}
