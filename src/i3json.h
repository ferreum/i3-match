
#ifndef _I3JSON_H_
#define _I3JSON_H_

#include "base.h"

#include <yajl/yajl_tree.h>
#include <stdio.h>

typedef enum iter_advise {
    ITER_CONT = 0,
    ITER_NODESC = 1,
    ITER_ABORT = 2,
    ITER_ABORT_SUCCESS = 3
} iter_advise;

typedef struct iter_info {
    int level;
    int floating;
    int nodei;
    int nodec;
    int subnodec;
} iter_info;

typedef iter_advise (i3json_iter_nodes_pred)(yajl_val node, iter_info *info, void *ptr);

extern iter_advise i3json_iter_nodes(yajl_val tree, i3json_iter_nodes_pred pred, void *ptr);

typedef enum matcher_type {
    MT_EQUALS = 0<<0,
    MT_STARTS = 1<<0,
    MT_ENDS = 2<<0,
    MT_CONTAINS = 3<<0,
    MT_NOT = 1<<4,
    MT_MASK_BASE = 0x0f
} matcher_type;

typedef struct i3json_matcher {
    unsigned int type;
    const char *key;
    size_t key_len;
    const char *pattern;
    size_t pattern_len;
} i3json_matcher;

extern int i3json_parse_matcher(const char *strdef, i3json_matcher *out);

extern int i3json_parse_operator(const char *str);

extern void i3json_make_matcher(const char *key, const char *pattern, unsigned int type, i3json_matcher *out);

extern void i3json_matcher_print(FILE *stream, i3json_matcher *matcher);

extern int i3json_matcher_match_value(const char* value, i3json_matcher *matcher);

extern int i3json_matcher_match(yajl_val node, i3json_matcher *matchers);

typedef const char *(i3json_value_getter)(const char *key, void *ptr);

extern int i3json_matchers_match_ex(int matcherc, i3json_matcher *matchers, i3json_value_getter *getter, void *ptr);

extern int i3json_matchers_match_node(yajl_val node, int matcherc, i3json_matcher *matchers);

extern yajl_val i3json_matchers_match_tree(yajl_val tree, int matcherc, i3json_matcher *matchers);

extern int i3json_matcher_cmp_key(i3json_matcher *matcher, const char* key);

extern yajl_val i3json_get_focus(yajl_val tree);

extern int i3json_is_scratch(yajl_val node);

extern yajl_val i3json_get_active_workspace(yajl_val tree);

typedef struct i3json_print_tree_context {
    int prevlevel;
    int scratch;
    int floating;
    int wslevel;
    const char *ws;
    int outputlevel;
    const char *output;
} i3json_print_tree_context;

#define I3JSON_EMPTY_PRINT_TREE_CONTEXT {.prevlevel = 0, .scratch = 0, .floating = 0}

extern void i3json_tree_accum_data(yajl_val node, iter_info *info, i3json_print_tree_context *context);

extern void i3json_print_tree_node(FILE *stream, int selected,
                                   yajl_val node, iter_info *info,
                                   i3json_print_tree_context *context,
                                   const char *text);

extern void i3json_print_tree(FILE *stream, yajl_val tree, yajl_val selected);

#endif /* _I3JSON_H_ */
