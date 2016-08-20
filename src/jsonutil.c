
#include "jsonutil.h"
#include "util.h"
#include "debug.h"
#include "base.h"

#include <yajl/yajl_gen.h>

#include <string.h>
#include <assert.h>

static void print_cb_fwrite(void *ctx, const char *str, size_t len) {
    FILE *f = ctx;
    fwrite(str, 1, len, f);
}

extern void yajlutil_print_cb_sb_push(void *ctx, const char *str, size_t len) {
    string_builder *sb = ctx;
    sb_pushn(sb, str, len);
}

static void check_status(yajl_gen_status status) {
    if (status != yajl_gen_status_ok) {
        fprintf(stderr, "yajl_gen_status was %d\n", (int) status);
        assert(0);
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
        assert(0);
    }
}

extern void yajlutil_push_tree(string_builder *sb, yajl_val tree, int parse_numbers) {
    yajl_gen gen;

    gen = yajl_gen_alloc(NULL);
    assert(gen);

    if (!yajl_gen_config(gen, yajl_gen_print_callback,
                         yajlutil_print_cb_sb_push, sb)) {
        fprintf(stderr, "yajl_gen_config failed\n");
        assert(0);
    }

    yajlutil_serialize_val(gen, tree, parse_numbers);
    yajl_gen_free(gen);
}

static void print_tree(FILE *f, yajl_val tree, int parse_numbers) {
    yajl_gen gen;

    gen = yajl_gen_alloc(NULL);
    if (!gen) {
        fprintf(stderr, "yajl_gen_alloc failed\n");
        assert(0);
    }

    if (!yajl_gen_config(gen, yajl_gen_beautify, 1)
        || !yajl_gen_config(gen, yajl_gen_validate_utf8, 1)
        || !yajl_gen_config(gen, yajl_gen_print_callback, print_cb_fwrite, f)) {
        fprintf(stderr, "yajl_gen_config failed\n");
        assert(0);
    }

    yajlutil_serialize_val(gen, tree, parse_numbers);
    yajl_gen_free(gen);
}

extern void dump_tree(FILE *stream, yajl_val tree) {
    print_tree(stream, tree, 0);
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
        assert(0);
    }
}

extern yajl_val yajlutil_path_get(yajl_val obj, const char *path, yajl_type type) {
    for (;;) {
        char *p = strchr(path, '/');
        const char *ykey[2] = {NULL, NULL};
        if (p) {
            size_t len = p - path;
            STACK_SUBSTR(key, path, len);
            debug_print("key=%s\n", key);
            ykey[0] = key;
            obj = yajl_tree_get(obj, ykey, yajl_t_any);
        } else {
            debug_print("lastkey=%s\n", path);
            ykey[0] = path;
            obj = yajl_tree_get(obj, ykey, type);
        }
        if (p && obj) {
            path = p + 1;
        } else {
            return obj;
        }
    }
}

