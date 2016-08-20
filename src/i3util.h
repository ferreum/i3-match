
#ifndef _I3UTIL_H_
#define _I3UTIL_H_

#include "i3ipc.h"

#include <yajl/yajl_tree.h>

typedef int (*wincheck_cb)(yajl_val obj, void *context);

extern int exec_wait(int sock, const char *spath, char *command);
extern int exec_wait_ex(int sock, const char *spath, char *command, long int timeout, wincheck_cb cb, void *context);

extern int i3util_request_json(int sock, int type, char *data, i3_msg *msg, yajl_val *jobj);

extern int i3util_subscribe(int sock, const char *data);

#endif /* _I3UTIL_H_ */
