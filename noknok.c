#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
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

static void handle_connection(int fd)
{
    /* only consider whatever comes in with the first read() */
    char buffer[1024];
    int r = read(fd, buffer, sizeof(buffer));
    if (r == -1 || r == 0)
        return;
    // TODO read context / username / password (all zero terminated) and reply
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
