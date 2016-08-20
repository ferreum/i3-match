
#ifndef _JSONUTIL_H_
#define _JSONUTIL_H_

#include "sb.h"

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#include <stdio.h>

extern void yajlutil_print_cb_sb_push(void *ctx, const char *str, size_t len);

extern void yajlutil_serialize_val(yajl_gen gen, yajl_val val, int parse_numbers);

extern void dump_tree(FILE *stream, yajl_val tree);

extern void yajlutil_push_tree(string_builder *sb, yajl_val tree, int parse_numbers);

extern char *yajlutil_get_string(yajl_val val);

extern yajl_val yajlutil_path_get(yajl_val obj, const char *path, yajl_type type);

#endif /* _JSONUTIL_H_ */
