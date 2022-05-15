
#include "i3util.h"
#include "i3json.h"
#include "jsonutil.h"
#include "util.h"
#include "debug.h"
#include "base.h"

#include <json-c/json_tokener.h>

#include <sys/socket.h>

#include <string.h>
#include <unistd.h>

extern int i3util_request_json(int sock, unsigned long type, char *data, i3_msg *msg, json_object **jobj) {
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
    enum json_tokener_error error;
    *jobj = json_tokener_parse_verbose(msg->data, &error);
    if (!*jobj) {
        msg->status = ST_INVALID_RESPONSE;
        jsonutil_print_error("response parse error", error);
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
    enum json_tokener_error error;
    json_object *resp = json_tokener_parse_verbose(msg.data, &error);
    int success = 0;
    if (!resp) {
        jsonutil_print_error("subscribe response parse error", error);
    } else {
        json_object *val;
        if (json_object_object_get_ex(resp, "success", &val)
            && json_object_is_type(val, json_type_boolean)) {
            success = json_object_get_boolean(val);
        }
        json_object_put(resp);
    }
    del_i3_msg(&msg);
    return success ? 0 : -1;
}

