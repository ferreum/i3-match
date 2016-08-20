
#include "i3json.h"
#include "jsonutil.h"
#include "util.h"
#include "debug.h"

#include <assert.h>
#include <string.h>

struct operator {
    const char const *str;
    const size_t len;
    const int type;
};

static const struct operator OPERATORS[] = {
    {"==", 2, MT_EQUALS},
    {"=^", 2, MT_STARTS},
    {"=$", 2, MT_ENDS},
    {"=*", 2, MT_CONTAINS},
    {"=", 1, MT_EQUALS},
    {"!=^", 3, MT_STARTS | MT_NOT},
    {"!=$", 3, MT_ENDS | MT_NOT},
    {"!=*", 3, MT_CONTAINS | MT_NOT},
    {"!=", 2, MT_EQUALS | MT_NOT},
};

extern int i3json_parse_matcher(const char *strdef, i3json_matcher *out) {
    int i;
    int numops = sizeof(OPERATORS) / sizeof(struct operator);
    const struct operator *best = NULL;
    int bestpos = -1;
    for (i = 0; i < numops; i++) {
        const char *p = strstr(strdef, OPERATORS[i].str);
        if (p) {
            int pos = p - strdef;
            if (!best || pos < bestpos) {
                best = OPERATORS + i;
                bestpos = pos;
            }
        }
    }
    if (best) {
        out->type = best->type;
        out->key = strdef;
        out->key_len = bestpos;
        out->pattern = strdef + bestpos + best->len;
        out->pattern_len = strlen(strdef) - bestpos - best->len;
        return 0;
    } else {
        return -1;
    }
}

extern int i3json_parse_operator(const char *str) {
    int numops = sizeof(OPERATORS) / sizeof(struct operator);
    int i;
    for (i = 0; i < numops; i++) {
        const struct operator *op = OPERATORS + i;
        if (strcmp(str, op->str) == 0) {
            return op->type;
        }
    }
    return -1;
}

#define PRINT_MATCHER_FMT "key=%*.*s pattern=%*.*s type=%d"
#define PRINT_MATCHER_ARGS(matcher) \
        (int) matcher->key_len, (int) matcher->key_len, matcher->key, \
        (int) matcher->pattern_len, (int) matcher->pattern_len, matcher->pattern, \
        matcher->type

extern void i3json_make_matcher(const char *key, const char *pattern, unsigned int type, i3json_matcher *out) {
    out->key = key;
    out->key_len = strlen(key);
    out->pattern = pattern;
    out->pattern_len = strlen(pattern);
    out->type = type;
    debug_print("matcher={" PRINT_MATCHER_FMT "}\n", PRINT_MATCHER_ARGS(out));
}

extern void i3json_matcher_print(FILE *stream, i3json_matcher *matcher) {
    fprintf(stream, PRINT_MATCHER_FMT, PRINT_MATCHER_ARGS(matcher));
}

extern int i3json_matcher_match_value(const char* value, i3json_matcher *matcher) {
    if (!value) {
        // Treat missing value as empty string.
        value = "";
    }
    size_t patlen = matcher->pattern_len;
    debug_print("pattern=%*.*s type=0x%x value=%s\n",
                (int) patlen, (int) patlen, matcher->pattern, matcher->type, value);
    int result;
    int basetype = matcher->type & MT_MASK_BASE;
    switch (basetype) {
    case MT_EQUALS:
        result = strncmp(value, matcher->pattern, patlen) == 0
                 && value[patlen] == '\0';
        break;
    case MT_STARTS:
        result = strncmp(value, matcher->pattern, patlen) == 0;
        break;
    case MT_ENDS: {
        size_t l = strlen(value);
        result = l >= patlen
                 && strncmp(value + l - patlen, matcher->pattern, patlen) == 0;
        break;
    }
    case MT_CONTAINS: {
        STACK_SUBSTR(pattern, matcher->pattern, patlen);
        result = strstr(value, pattern) != NULL;
        break;
    }
    default:
        fprintf(stderr, "basetype=%x\n", basetype);
        assert(0);
    }
    if (matcher->type & MT_NOT) {
        result = !result;
    }
    return result;
}

extern int i3json_matcher_match(yajl_val node, i3json_matcher *matcher) {
    size_t keylen = matcher->key_len;
    STACK_SUBSTR(key, matcher->key, keylen);
    yajl_val jobj = yajlutil_path_get(node, key, yajl_t_any);
    const char *value = yajlutil_get_string(jobj);
    return i3json_matcher_match_value(value, matcher);
}

extern int i3json_matchers_match_ex(int matcherc, i3json_matcher *matchers, i3json_value_getter *getter, void *ptr) {
    int i;
    for (i = 0; i < matcherc; i++) {
        i3json_matcher *matcher = matchers + i;
        size_t keylen = matcher->key_len;
        STACK_SUBSTR(key, matcher->key, keylen);
        const char *value = getter(key, ptr);
        if (!i3json_matcher_match_value(value, matcher)) {
            return 0;
        }
    }
    return 1;
}

extern int i3json_matchers_match_node(yajl_val node, int matcherc, i3json_matcher *matchers) {
    int i;
    for (i = 0; i < matcherc; i++) {
        if (!i3json_matcher_match(node, matchers + i)) {
            return 0;
        }
    }
    return 1;
}

typedef struct {
    int matcherc;
    i3json_matcher *matchers;
    yajl_val result;
} matcher_pred_args;

static iter_advise matcher_pred(yajl_val node, __unused iter_info *info, void *ptr) {
    matcher_pred_args *args = ptr;
    if (i3json_matchers_match_node(node, args->matcherc, args->matchers)) {
        args->result = node;
        return ITER_ABORT_SUCCESS;
    } else {
        return ITER_CONT;
    }
}

extern yajl_val i3json_matchers_match_tree(yajl_val tree, int matcherc, i3json_matcher *matchers) {
    matcher_pred_args args = { .matcherc = matcherc, .matchers = matchers };
    if (i3json_iter_nodes(tree, &matcher_pred, &args) == ITER_ABORT_SUCCESS) {
        return args.result;
    } else {
        return NULL;
    }
}

extern int i3json_matcher_cmp_key(i3json_matcher *matcher, const char* key) {
    size_t keylen = matcher->key_len;
    int r;
    if ((r = strncmp(matcher->key, key, keylen)) == 0) {
        if (strlen(key) > keylen) {
            r = -1;
        }
    }
    return r;
}

static iter_advise focus_pred(yajl_val node, __unused iter_info *info, void *ptr) {
    const char *ykey[] = {"focused", NULL};
    yajl_val yo = yajl_tree_get(node, ykey, yajl_t_true);
    if (YAJL_IS_TRUE(yo)) {
        yajl_val *pmatch = ptr;
        *pmatch = node;
        return ITER_ABORT_SUCCESS;
    } else {
        return ITER_CONT;
    }
}

yajl_val i3json_get_focus(yajl_val tree) {
    yajl_val match = NULL;
    if (i3json_iter_nodes(tree, &focus_pred, &match) == ITER_ABORT_SUCCESS) {
        return match;
    }
    return NULL;
}

int i3json_is_scratch(yajl_val node) {
    const char *ykey[] = {"scratchpad_state", NULL};
    yajl_val yo = yajl_tree_get(node, ykey, yajl_t_string);
    const char *state = YAJL_GET_STRING(yo);
    return state && state[0] && strcmp(state, "none") != 0;
}

static iter_advise active_ws_pred(yajl_val node, __unused iter_info *info, void *ptr) {
    const char *ykey[] = {"type", NULL};
    yajl_val yo = yajl_tree_get(node, ykey, yajl_t_string);
    const char *type = YAJL_GET_STRING(yo);
    if (strcmp(type, "workspace") == 0) {
        if (i3json_get_focus(node) != NULL) {
            yajl_val *pws = ptr;
            *pws = node;
            return ITER_ABORT_SUCCESS;
        } else {
            return ITER_NODESC;
        }
    } else {
        return ITER_CONT;
    }
}

yajl_val i3json_get_active_workspace(yajl_val tree) {
    yajl_val ws;
    iter_advise adv = i3json_iter_nodes(tree, &active_ws_pred, &ws);
    switch (adv) {
    case ITER_ABORT_SUCCESS:
        return ws;
    default:
        return NULL;
    }
}

static void printflag(FILE *stream, const char *flag, int value) {
    if (!value) {
        fprintf(stream, "-");
    } else if (value == 1) {
        fprintf(stream, "%s", flag);
    } else if (value >= 10) {
        fprintf(stream, "x");
    } else {
        fprintf(stream, "%d", value);
    }
}

static int is_type(yajl_val node, const char *type) {
    const char *ykey[] = {"type", NULL};
    yajl_val tmp = yajl_tree_get(node, ykey, yajl_t_string);
    const char *ntype = YAJL_GET_STRING(tmp);
    return ntype && strcmp(ntype, type) == 0;
}

#define ACCUM_DATA(levelvar, cond, level, prevlevel, assign, reset) \
do {                                                                \
    int __val = levelvar;                                           \
    if (__val) {                                                    \
        __val += level - prevlevel;                                 \
        if (__val <= 1) { __val = 0; { reset }; }                   \
        levelvar = __val;                                           \
    }                                                               \
    if (!__val && (cond)) {                                         \
        levelvar = 1;                                               \
        { assign };                                                 \
    }                                                               \
} while (0)

#define ACCUM_LEVEL(field, cond, level, prevlevel) \
    ACCUM_DATA(field, cond, level, prevlevel, {}, {})

void i3json_tree_accum_data(yajl_val node, iter_info *info, i3json_print_tree_context *context) {
    ACCUM_LEVEL(context->scratch, i3json_is_scratch(node), info->level, context->prevlevel);
    ACCUM_LEVEL(context->floating, info->floating, info->level, context->prevlevel);
    const char *ykey[] = {"name", NULL};
    ACCUM_DATA(context->wslevel, is_type(node, "workspace"), info->level, context->prevlevel, {
        yajl_val tmp = yajl_tree_get(node, ykey, yajl_t_string);
        context->ws = YAJL_GET_STRING(tmp);
    }, {
        context->ws = NULL;
    });
    ACCUM_DATA(context->outputlevel, is_type(node, "output"), info->level, context->prevlevel, {
        yajl_val tmp = yajl_tree_get(node, ykey, yajl_t_string);
        context->output = YAJL_GET_STRING(tmp);
    }, {
        context->output = NULL;
    });
    context->prevlevel = info->level;
}

void i3json_print_tree_node(FILE *stream, int selected,
                            yajl_val node, iter_info *info,
                            i3json_print_tree_context *context,
                            const char *text) {
    int i;
    char *indent = "--";
    if (selected) {
        indent = "==";
    }
    for (i = info->level; i > 0; i--) {
        fprintf(stream, indent);
    }
    if (text) {
        fprintf(stream, "%s\n", text);
    } else {
        char type;
        {
            const char *ykey[] = {"type", NULL};
            yajl_val yo = yajl_tree_get(node, ykey, yajl_t_string);
            const char *state = YAJL_GET_STRING(yo);
            if (state && state[0]) {
                type = state[0];
            } else {
                type = '?';
            }
        }
        fprintf(stream, " ");
        fprintf(stream, "%c", type);
        printflag(stream, "s", context->scratch);
        printflag(stream, "f", context->floating);
        fprintf(stream, " ");
        const char *ykey[] = {"name", NULL};
        yajl_val nobj = yajl_tree_get(node, ykey, yajl_t_string);
        const char *name = YAJL_GET_STRING(nobj);
        if (!name) {
            name = "";
        }
        fprintf(stream, "%s\n", name);
    }
}

typedef struct {
    FILE *stream;
    yajl_val selected;
    i3json_print_tree_context pt_context;
} print_pred_args;

static iter_advise print_pred(yajl_val node, iter_info *info, void *ptr) {
    print_pred_args *args = ptr;
    i3json_tree_accum_data(node, info, &args->pt_context);
    i3json_print_tree_node(args->stream, node == args->selected,
                           node, info, &args->pt_context, NULL);
    return ITER_CONT;
}

extern void i3json_print_tree(FILE *stream, yajl_val tree, yajl_val selected) {
    print_pred_args args = {
        .stream = stream,
        .selected = selected,
        .pt_context = I3JSON_EMPTY_PRINT_TREE_CONTEXT,
    };
    i3json_iter_nodes(tree, &print_pred, &args);
}

static iter_advise i3json_iter_nodes_recurse(yajl_val tree, iter_info *info, i3json_iter_nodes_pred pred, void *ptr) {
    static const char const *keys[] = {"nodes", "floating_nodes"};
    int ki;
    int subnodec = 0;
    const char *ykey[2] = {NULL, NULL};
    for (ki = 0; ki < 2; ki++) {
        ykey[0] = keys[ki];
        yajl_val tmp = yajl_tree_get(tree, ykey, yajl_t_array);
        if (YAJL_IS_ARRAY(tmp)) {
            subnodec += YAJL_GET_ARRAY(tmp)->len;
        }
    }
    info->subnodec = subnodec;
    iter_advise adv = pred(tree, info, ptr);
    switch (adv) {
    case ITER_CONT:
        // Descend to children.
        break;
    case ITER_NODESC:
        return ITER_CONT;
    case ITER_ABORT:
    case ITER_ABORT_SUCCESS:
        return adv;
    }
    int nodei = 0;
    for (ki = 0; ki < 2; ki++) {
        ykey[0] = keys[ki];
        yajl_val nodes = yajl_tree_get(tree, ykey, yajl_t_array);
        if (YAJL_IS_ARRAY(nodes)) {
            int numnodes = nodes->u.array.len;
            int i;
            for (i = 0; i < numnodes; i++) {
                yajl_val node = nodes->u.array.values[i];
                iter_info subinfo = { .level = info->level + 1, .floating = ki == 1, .nodei = nodei, .nodec = subnodec};
                iter_advise subadv = i3json_iter_nodes_recurse(node, &subinfo, pred, ptr);
                switch (subadv) {
                case ITER_CONT:
                    // Continue iteration.
                    break;
                case ITER_NODESC:
                    // ITER_NODESC is never returned.
                    assert(0);
                case ITER_ABORT:
                case ITER_ABORT_SUCCESS:
                    return subadv;
                }
                nodei++;
            }
        }
    }
    return ITER_CONT;
}

iter_advise i3json_iter_nodes(yajl_val tree, i3json_iter_nodes_pred pred, void *ptr) {
    iter_info info = { .level = 0, .floating = 0, .nodei = 0, .nodec = 1 };
    return i3json_iter_nodes_recurse(tree, &info, pred, ptr);
}

