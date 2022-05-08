
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

extern int i3util_request_json(int sock, unsigned long type, char *data, i3_msg *msg, yajl_val *jobj) {
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

