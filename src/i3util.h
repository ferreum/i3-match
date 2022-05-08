
#ifndef _I3UTIL_H_
#define _I3UTIL_H_

#include "i3ipc.h"

#include <yajl/yajl_tree.h>

extern int i3util_request_json(int sock, unsigned long type, char *data, i3_msg *msg, yajl_val *jobj);

extern int i3util_subscribe(int sock, const char *data);

#endif /* _I3UTIL_H_ */
