
#include "i3ipc.h"
#include "util.h"
#include "debug.h"

#include "root_atom_contents.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdarg.h>

const char *i3ipc_get_env_sockpath(void) {
    return getenv("I3_SOCKET");
}

char *i3ipc_get_xcb_sockpath(void) {
    return root_atom_contents("I3_SOCKET_PATH", NULL, 0);
}

char *i3ipc_get_cmd_sockpath(void) {
    int fd_p[2];
    if (pipe(fd_p) == -1) {
        perror("pipe");
        return NULL;
    }
    switch (fork()) {
    case -1:
        perror("fork");
        return NULL;
    case 0: {
        close(fd_p[0]);
        close(STDOUT_FILENO);
        dup2(fd_p[1], STDOUT_FILENO);
        close(fd_p[1]);
        char *args[] = { "i3", "--get-socketpath", NULL };
        if (execvp("i3", args) == -1) {
            perror("execvp i3");
        }
        // not reached on success
        assert(0);
    }
    default: {
        close(fd_p[1]);
        FILE *f = fdopen(fd_p[0], "r");
        char *line = read_line(f);
        fclose(f);
        return line;
    }
    }
}

const char *i3ipc_get_sockpath(char **a_path) {
    assert(a_path != NULL);
    const char *path = i3ipc_get_env_sockpath();
    debug_print("env path=%s\n", path);
    if (!path || !path[0]) {
        path = *a_path = i3ipc_get_xcb_sockpath();
        debug_print("xcb path=%s\n", path);
        if (!path) {
            path = *a_path = i3ipc_get_cmd_sockpath();
            debug_print("cmd path=%s\n", path);
            if (!path) {
                return NULL;
            }
        }
    }
    return path;
}

int i3ipc_open_socket(const char *path) {
    char *a_path = NULL;
    if (!path) {
        path = i3ipc_get_sockpath(&a_path);
    }

    struct sockaddr_un remote;
    int s;
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        free(a_path);
        return -1;
    }

    debug_print("%s\n", "trying to connect...");

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, path, sizeof(remote.sun_path));
    remote.sun_path[sizeof(remote.sun_path) - 1] = '\0';
    socklen_t len = strlen(path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
        close(s);
        free(a_path);
        return -1;
    }

    debug_print("%s\n", "connected.");

    free(a_path);
    return s;
}

int i3ipc_send_message(int sock, int type, const char *data) {
    assert(sock >= 0);
    assert(type >= 0 && type < 7);
    i3_ipc_header_t hdr;
    size_t datalen = data == NULL ? 0 : strlen(data);

    strncpy(hdr.magic, I3_IPC_MAGIC, sizeof(hdr.magic));
    hdr.size = datalen;
    hdr.type = type;
    int res;
    if ((res = send(sock, &hdr, sizeof(hdr), 0)) == -1) {
        return res;
    }
    if (datalen > 0) {
        if ((res = send(sock, data, datalen, 0)) == -1) {
            return res;
        }
    }
    return res;
}

int i3ipc_recv_message(int sock, i3_msg *msg) {
    assert(sock >= 0);
    assert(msg != NULL);
    ssize_t l;
    // get the header
    i3_ipc_header_t hdr;
    if ((l = recv(sock, &hdr, sizeof(i3_ipc_header_t), MSG_WAITALL)) == -1) {
        msg->status = ST_SOCK_ERROR;
        return -1;
    }
    // check header
    if ((size_t) l != sizeof(i3_ipc_header_t)
        || strncmp(I3_IPC_MAGIC, hdr.magic, sizeof(hdr.magic)) != 0) {
        msg->status = ST_INVALID_HEADER;
        return -1;
    }
    size_t len = hdr.size;
    char *dbuf;
    char *oldbuf = NULL;
    char *mybuf = NULL;
    // get the data
    if (msg->blen < len + 1) { // add 1 for '\0'
        debug_print("alloc to %ld\n", len + 1);
        oldbuf = msg->data;
        mybuf = dbuf = malloc(len + 1);
    } else {
        dbuf = msg->data;
    }
    if ((l = recv(sock, dbuf, len, MSG_WAITALL)) == -1) {
        int e = errno;
        free(mybuf);
        errno = e;
        msg->status = ST_SOCK_ERROR;
        return -1;
    }
    if ((size_t) l != len) {
        free(mybuf);
        msg->status = ST_DATA_ERROR;
        return -1;
    }
    dbuf[len] = '\0'; // set last char in buffer
    if (oldbuf) {
        free(oldbuf);
        msg->blen = len + 1;
    }
    msg->status = ST_OK;
    msg->type = hdr.type;
    msg->data = dbuf;
    msg->len = len;
    return 0;
}

void i3ipc_print_error(int status) {
    switch (status) {
    case ST_SOCK_ERROR:
        perror("i3ipc_recv_message");
        break;
    case ST_INVALID_HEADER:
        fprintf(stderr, "invalid response header\n");
        break;
    case ST_DATA_ERROR:
        fprintf(stderr, "invalid response\n");
        break;
    default:
        fprintf(stderr, "unknown error\n");
        break;
    }
}

int i3ipc_request(int s, int type, const char *data, i3_msg *msg) {
    debug_print("%s\n", "sending...");
    if (i3ipc_send_message(s, type, data) == -1) {
        perror("i3ipc_send_message");
        return -1;
    }

    debug_print("%s\n", "receiving...");
    if (i3ipc_recv_message(s, msg) == -1) {
        i3ipc_print_error(msg->status);
        return -1;
    }
    if (msg->type != type) {
        msg->status = ST_INVALID_RESPONSE;
        del_i3_msg(msg);
        return -1;
    }
    return 0;
}

static int i3ipc_send_commandfv(int sock, char *buf, size_t size, char *fmt, va_list ap) {
    vsnprintf(buf, size, fmt, ap);
    debug_print("command=%s\n", buf);
    return i3ipc_send_message(sock, I3_IPC_MESSAGE_TYPE_COMMAND, buf);
}

int i3ipc_send_commandf(int sock, char *buf, size_t size, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int result = i3ipc_send_commandfv(sock, buf, size, fmt, ap);
    va_end(ap);
    return result;
}

int i3ipc_send_ccommandf(int sock, char *buf, size_t size, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int result = i3ipc_send_commandfv(sock, buf, size, fmt, ap);
    va_end(ap);
    i3_msg msg;
    if (result != -1) {
        debug_print("%s\n", "checking response...");
        if (i3ipc_recv_skip(sock, &msg) == -1) {
            debug_print("%s\n", "receive failed");
            return -1;
        }
        if (msg.type != I3_IPC_REPLY_TYPE_COMMAND) {
            debug_print("invalid response type: 0x%x\n", msg.type);
            result = -1;
        }
    }
    return result;
}

int i3ipc_send_ccommand(int sock, const char *data) {
    if (i3ipc_send_message(sock, I3_IPC_MESSAGE_TYPE_COMMAND, data) == -1) {
        return -1;
    }
    i3_msg msg = EMPTY_I3_MSG;
    if (i3ipc_recv_skip(sock, &msg) == -1) {
        debug_print("%s\n", "receive failed");
        return -1;
    }
    if (msg.type != I3_IPC_REPLY_TYPE_COMMAND) {
        debug_print("invalid response type: 0x%x\n", msg.type);
        return -1;
    }
    return 0;
}

extern int i3ipc_recv_skip(int sock, i3_msg *msg) {
    ssize_t l;
    i3_ipc_header_t hdr;
    if ((l = recv(sock, &hdr, sizeof(i3_ipc_header_t), MSG_WAITALL)) == -1) {
        perror("recv");
        if (msg) msg->status = ST_SOCK_ERROR;
        return -1;
    }
    if ((size_t) l != sizeof(i3_ipc_header_t)
        || strncmp(I3_IPC_MAGIC, hdr.magic, sizeof(hdr.magic)) != 0) {
        debug_print("%s\n", "invalid header");
        if (msg) msg->status = ST_INVALID_HEADER;
        return -1;
    }
    size_t len = hdr.size;
    if (msg) {
        msg->type = hdr.type;
        msg->len = len;
    }
    int result = 0;
    if (len > 0) {
        char buf[BUFSIZ];
        size_t n;

        debug_print("reading %ld bytes...\n", len);

        ssize_t r;
        do {
            n = len > BUFSIZ ? BUFSIZ : len;
            r = (recv(sock, &buf, n, MSG_WAITALL));
            if (r == -1) {
                int e = errno;
                if (msg) msg->status = ST_SOCK_ERROR;
                errno = e;
                result = -1;
            } else {
                len -= r;
            }
        } while (r != -1 && len > 0);
    }
    if (len == 0) {
        if (msg) msg->status = ST_OK;
    }
    return result;
}

void del_i3_msg(i3_msg *msg) {
    assert(msg != NULL);
    msg->status = ST_UNKNOWN;
    msg->type = -1;
    if (msg->data) {
        free(msg->data);
        msg->data = NULL;
        msg->blen = 0;
    } else {
        assert(msg->blen == 0);
    }
}

void i3ipc_msg_recycle(i3_msg *msg) {
    assert(msg != NULL);
    if (msg->data) {
        msg->status = ST_RECYCLED;
        msg->type = -1;
    } else {
        msg->status = ST_UNKNOWN;
    }
}

