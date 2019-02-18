
#include "i3util.h"
#include "i3json.h"
#include "jsonutil.h"
#include "util.h"
#include "debug.h"
#include "base.h"
#include "sockutil.h"

#include <sys/socket.h>

#include <assert.h>
#include <string.h>
#include <unistd.h>

static int exec_command(int sock, char *command) {
    char buf[BUFSIZ];
    return i3ipc_send_ccommandf(
        sock, buf, BUFSIZ,
        "workspace back_and_forth, exec %s, workspace back_and_forth",
        command);
}

static int check_event(i3_msg *msg, wincheck_cb cb, void *context) {
    int matches = 0;
    if (msg->type == I3_IPC_EVENT_WINDOW) {
        char errbuf[ERROR_BUFSIZ];
        yajl_val info = yajl_tree_parse(msg->data, errbuf, sizeof(errbuf));
        if (!info) {
            print_error("parse error", errbuf);
            return 0;
        }

        const char *ykey[] = {"change", NULL};
        yajl_val jchange = yajl_tree_get(info, ykey, yajl_t_string);
        const char *change = YAJL_GET_STRING(jchange);
        if (strcmp(change, "new") == 0) {
            if (cb) {
                ykey[0] = "container";
                yajl_val jcontainer = yajl_tree_get(info, ykey, yajl_t_object);
                matches = cb(jcontainer, context);
            } else {
                matches = 1;
            }
        }

        yajl_tree_free(info);
    }
    return matches;
}

int exec_wait_ex(int sock, const char *spath, char *command, long int timeout, wincheck_cb cb, void *context) {
    debug_print("%s\n", "subscribing...");
    int subsock = i3ipc_open_socket(spath);
    if (subsock == -1) {
        fprintf(stderr, "failed to open subscribe socket\n");
        return -1;
    }
    int result = -1;

    if (timeout != 0) {
        sock_set_timeout(subsock, timeout);
    }

    // subscribe to window events
    if (i3util_subscribe(subsock, "[\"window\"]") == -1) {
        fprintf(stderr, "failed to subscribe to window events\n");
    } else {
        // start process and wait for window
        debug_print("%s\n", "starting command...");
        if (exec_command(sock, command) == -1) {
            fprintf(stderr, "failed to execute command\n");
        } else {
            debug_print("%s\n", "waiting for window...");
            int c;
            i3_msg msg = EMPTY_I3_MSG;
            while ((c = i3ipc_recv_message(subsock, &msg)) != -1) {
                // will receive pending responses from exec_command first
                debug_print(
                    "message: event=%d type=%ld\n",
                    (msg.type & I3_IPC_EVENT_MASK) != 0,
                    (msg.type & ~I3_IPC_EVENT_MASK));
                if (check_event(&msg, cb, context)) {
                    debug_print("%s\n", "found window");
                    result = 0;
                    break;
                }
                del_i3_msg(&msg);
            }
            if (c == -1) {
                perror("i3ipc_recv_message");
            } else {
                del_i3_msg(&msg);
            }
        }
    }
    close(subsock);
    return result;
}

int i3util_request_json(int sock, unsigned long type, char *data, i3_msg *msg, yajl_val *jobj) {
    debug_print("%s\n", "sending...");
    if (i3ipc_send_message(sock, type, data) == -1) {
        perror("i3ipc_send_message");
        return -1;
    }

    debug_print("%s\n", "receiving...");
    if (i3ipc_recv_message(sock, msg) == -1) {
        i3ipc_print_error(msg->status);
        return -1;
    }
    if (msg->type != type) {
        msg->status = ST_INVALID_RESPONSE;
        del_i3_msg(msg);
        return -1;
    }
    char errbuf[ERROR_BUFSIZ];
    *jobj = yajl_tree_parse(msg->data, errbuf, sizeof(errbuf));
    if (!*jobj) {
        msg->status = ST_INVALID_RESPONSE;
        print_error("parse error", errbuf);
        return -1;
    }
    return 0;
}

extern int i3util_subscribe(int sock, const char *data) {
    i3_msg msg = EMPTY_I3_MSG;
    if (i3ipc_request(sock, I3_IPC_MESSAGE_TYPE_SUBSCRIBE, data, &msg) == -1) {
        return -1;
    }
    // check subscribe success
    char errbuf[ERROR_BUFSIZ];
    yajl_val resp = yajl_tree_parse(msg.data, errbuf, sizeof(errbuf));
    int success = 0;
    if (!resp) {
        print_error("parse error", errbuf);
    } else {
        const char *path[] = {"success", NULL};
        yajl_val val = yajl_tree_get(resp, path, yajl_t_true);
        success = YAJL_IS_TRUE(val);
        yajl_tree_free(resp);
    }
    del_i3_msg(&msg);
    return success ? 0 : -1;
}

