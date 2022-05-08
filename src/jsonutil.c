#include "jsonutil.h"
#include "util.h"
#include "debug.h"
#include "base.h"

#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>

#include <string.h>
#include <stdlib.h>

extern void yajlutil_print_cb_sb_push(void *ctx, const char *str, size_t len) {
    string_builder *sb = ctx;
    sb_pushn(sb, str, len);
}

static void check_status(yajl_gen_status status) {
    if (status != yajl_gen_status_ok) {
        fprintf(stderr, "yajl_gen_status was %d\n", (int) status);
        abort();
    }
}

extern void yajlutil_serialize_val(yajl_gen gen, yajl_val val, int parse_numbers) {
    size_t i;
    switch (val->type) {
    case yajl_t_string:
        check_status(yajl_gen_string(gen,
                                     (const unsigned char *) val->u.string,
                                     strlen(val->u.string)));
        break;
    case yajl_t_number:
        if (parse_numbers && YAJL_IS_INTEGER(val)) {
            check_status(yajl_gen_integer(gen, YAJL_GET_INTEGER(val)));
        } else if (parse_numbers  &&  YAJL_IS_DOUBLE(val)) {
            check_status(yajl_gen_double(gen, YAJL_GET_DOUBLE(val)));
        } else {
            check_status(yajl_gen_number(gen, YAJL_GET_NUMBER(val),
                                         strlen(YAJL_GET_NUMBER(val))));
        }
        break;
    case yajl_t_object:
        check_status(yajl_gen_map_open(gen));
        for (i = 0; i < val->u.object.len ; i++) {
            check_status(yajl_gen_string(gen,
                                         (const unsigned char *) val->u.object.keys[i],
                                         strlen(val->u.object.keys[i])));
            yajlutil_serialize_val(gen, val->u.object.values[i], parse_numbers);
        }
        check_status(yajl_gen_map_close(gen));
        break;
    case yajl_t_array:
        check_status(yajl_gen_array_open(gen));
        for (i = 0; i < val->u.array.len; i++)
            yajlutil_serialize_val(gen, val->u.array.values[i], parse_numbers);
        check_status(yajl_gen_array_close(gen));
        break;
    case yajl_t_true:
        check_status(yajl_gen_bool(gen, 1));
        break;
    case yajl_t_false:
        check_status(yajl_gen_bool(gen, 0));
        break;
    case yajl_t_null:
        check_status(yajl_gen_null(gen));
        break;
    default:
        fprintf(stderr, "unexpectedly got type %d\n", (int) val->type);
        abort();
    }
}

extern char *yajlutil_get_string(yajl_val val) {
    if (!val) {
        return "";
    }
    switch (val->type) {
    case yajl_t_string:
        return YAJL_GET_STRING(val);
    case yajl_t_number:
        return YAJL_GET_NUMBER(val);
    case yajl_t_object:
        return NULL;
    case yajl_t_array:
        return NULL;
    case yajl_t_true:
        return "true";
        break;
    case yajl_t_false:
        return "false";
    case yajl_t_null:
        return "";
    default:
        fprintf(stderr, "unexpectedly got type %d\n", (int) val->type);
        abort();
    }
}

extern yajl_val yajlutil_path_get(yajl_val obj, const char *path, yajl_type type) {
    for (;;) {
        char *p = strchr(path, '/');
        const char *ykey[2] = {NULL, NULL};
        const char *keyend = p ? p : path + strlen(path);
        int keylen = keyend - path;
        if (YAJL_IS_ARRAY(obj)) {
            debug_print("array key=%.*s\n", keylen, path);
            char *end = NULL;
            int index = strtol(path, &end, 10);
            debug_print("used array key=%.*s\n", (int) (end - path), path);
            if (end != keyend) {
                return NULL;
            }
            if (index < 0) {
                index += obj->u.array.len;
            }
            if (index < 0 || (size_t) index >= obj->u.array.len) {
                return NULL;
            } else {
                obj = obj->u.array.values[index];
            }
        } else {
            STACK_SUBSTR(key, path, keylen);
            debug_print("key=%s\n", key);
            ykey[0] = key;
            obj = yajl_tree_get(obj, ykey, yajl_t_any);
        }
        if (!p) {
            if (type == yajl_t_any || (obj && obj->type == type)) {
                return obj;
            } else {
                return NULL;
            }
        } else if (!obj) {
            return NULL;
        } else {
            path = p + 1;
        }
    }
}
