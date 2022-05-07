/*
 * A program for matching containers in the i3 window manager.
 *
 * needed libraries: yajl
 *
 * Created:     2014-03-11
 * Last Change: 2014-03-14
 *
 */

#include "i3util.h"
#include "i3ipc.h"
#include "i3json.h"
#include "debug.h"
#include "jsonutil.h"
#include "util.h"
#include "sb.h"

#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef ASCII_TREE
// Unicode version of indent tree strings.
// Strings used for nodes.
#define IT_MID_CHILD "\u251c\u2500"
#define IT_LAST_CHILD "\u2514\u2500"
// String used for the root node. Should be one
// cell shorter than IT_BAR and IT_EMPTY.
#define IT_ROOT "\u2500"
// Strings used for indenting, the last character
// is removed when indenting for the root node.
#define IT_BAR "\u2502  "
#define IT_EMPTY "   "
#else
// Ascii version of indent tree strings.
#define IT_ROOT "-"
#define IT_MID_CHILD "+-"
#define IT_BAR "|  "
#define IT_EMPTY "   "
#define IT_LAST_CHILD "`-"
#endif

#define COL_BOLD "\x1b[1m"
#define COL_NORMAL "\x1b[m"

#define CH_SPACE ' '
#define CH_BAR '|'

const char *ALL_EVENTS_SUB_JSON_I3 = "[\"workspace\",\"output\",\"mode\",\"window\",\"barconfig_update\",\"binding\",\"shutdown\",\"tick\"]";
const char *ALL_EVENTS_SUB_JSON_SWAY = "[\"workspace\",\"mode\",\"window\",\"barconfig_update\",\"binding\",\"shutdown\",\"tick\",\"bar_state_update\",\"input\"]";

#define EVENT_TYPE_COUNT 8
const char *EVENT_NAMES[EVENT_TYPE_COUNT] = {
    "workspace", // (I3_IPC_EVENT_MASK | 0)
    "output", // (I3_IPC_EVENT_MASK | 1)
    "mode", // (I3_IPC_EVENT_MASK | 2)
    "window", // (I3_IPC_EVENT_MASK | 3)
    "barconfig_update", // (I3_IPC_EVENT_MASK | 4)
    "binding", // (I3_IPC_EVENT_MASK | 5)
    "shutdown", // (I3_IPC_EVENT_MASK | 6)
    "tick", // (I3_IPC_EVENT_MASK | 7)
};
#define EVENT_TYPE_SWAY_COUNT 2
#define EVENT_TYPE_SWAY_OFFSET 0x14
#define EVENT_TYPE_SWAY_FIRST (I3_IPC_EVENT_MASK | EVENT_TYPE_SWAY_COUNT)
const char *EVENT_NAMES_SWAY[EVENT_TYPE_SWAY_COUNT] = {
    "bar_state_update", // (I3_IPC_EVENT_MASK | 0x14)
    "input", // (I3_IPC_EVENT_MASK | 0x15)
};

#define TREE_OUTPUTS_COUNT 2
char *TREE_OUTPUTS[TREE_OUTPUTS_COUNT] = { ":itree", "name" };

#define DEFAULT_MONITOR_OUTPUT_COUNT 7
char *DEFAULT_MONITOR_OUTPUTS[DEFAULT_MONITOR_OUTPUT_COUNT] = {
    ":evtype", "change", "current/name", "container/name", "binding/command", "payload", "input/identifier"
};

typedef enum mode {
    MODE_MATCH = 0,
    MODE_SUBSCRIBE = 1,
} mode;

typedef enum outmode {
    OUT_NONE = 0,
    OUT_FIELDS = 1,
} outmode;

enum flags {
    F_PRINTALL = 1<<0,
    F_HIGHLIGHT = 1<<1,
    F_FLUSH = 1<<2,
};

typedef struct context {
    i3json_matcher *matchers;
    int matcherc;
    outmode outmode;
    char **outputs;
    int outputc;
    int flags;
    int maxcount;
    char *field_sep;
    size_t field_sep_len;
    int swaymode;
    string_builder sb;
    string_builder itree;
    int objcount;
    int matchcount;
    i3json_print_tree_context pt_context;
    i3_msg *msg;
    // yajl generator on sb.
    yajl_gen sb_gen;
} context;

static const char *get_eventtype(unsigned int type) {
    if ((type & I3_IPC_EVENT_MASK) != I3_IPC_EVENT_MASK) {
        return "none";
    }
    unsigned int i = type & ~I3_IPC_EVENT_MASK;
    if (i >= EVENT_TYPE_SWAY_FIRST) {
        i -= EVENT_TYPE_SWAY_OFFSET;
        if (i < EVENT_TYPE_SWAY_COUNT) {
            return EVENT_NAMES_SWAY[i];
        }
    } else if (i < EVENT_TYPE_COUNT) {
        return EVENT_NAMES[i];
    }
    return "unknown";
}

static yajl_gen get_sb_gen(context *context) {
    yajl_gen gen = context->sb_gen;
    if (!gen) {
        gen = yajl_gen_alloc(NULL);
        malloc_check(gen);
        int res = yajl_gen_config(gen, yajl_gen_print_callback,
                                  yajlutil_print_cb_sb_push, &context->sb);
        assert(res);
        context->sb_gen = gen;
    } else {
        yajl_gen_reset(gen, NULL);
    }
    return gen;
}

static void push_value(string_builder *sb, const char* key,
                       yajl_val node, iter_info *info,
                       context *ctx, int match) {
    debug_print("key=%s\n", key);
    if (strcmp(":match", key) == 0) {
        sb_pushf(sb, "%d", !!match);
    } else if (strcmp(":level", key) == 0) {
        sb_pushf(sb, "%d", info->level);
    } else if (strcmp(":floating", key) == 0) {
        sb_pushf(sb, "%d", ctx->pt_context.floating);
    } else if (strcmp(":scratch", key) == 0) {
        sb_pushf(sb, "%d", ctx->pt_context.scratch);
    } else if (strcmp(":workspace", key) == 0) {
        if (ctx->pt_context.ws) {
            sb_pushf(sb, "%s", ctx->pt_context.ws);
        }
    } else if (strcmp(":output", key) == 0) {
        if (ctx->pt_context.output) {
            sb_pushf(sb, "%s", ctx->pt_context.output);
        }
    } else if (strcmp(":sibi", key) == 0) {
        sb_pushf(sb, "%d", info->nodei);
    } else if (strcmp(":sibc", key) == 0) {
        sb_pushf(sb, "%d", info->nodec);
    } else if (strcmp(":childc", key) == 0) {
        sb_pushf(sb, "%d", info->subnodec);
    } else if (strcmp(":indent", key) == 0) {
        const char *str = match ? "--" : "  ";
        int j = info->level; // indent level + 1 times
        for (; j >= 0; j--) {
            sb_pushn(sb, str, 2);
        }
    } else if (strcmp(":itree", key) == 0) {
        string_builder *isb = &ctx->itree;
        int n = info->level;
        int j;
        for (j = 0; j < n; j++) {
            if (isb->buf[j] == CH_SPACE) {
                sb_pushn(sb, IT_EMPTY, strlen(IT_EMPTY) - !j);
            } else {
                sb_pushn(sb, IT_BAR, strlen(IT_BAR) - !j);
            }
        }
        if (info->level == 0) {
            sb_push(sb, IT_ROOT);
        } else if (info->nodei < info->nodec - 1) {
            sb_push(sb, IT_MID_CHILD);
        } else {
            sb_push(sb, IT_LAST_CHILD);
        }
    } else if (strcmp(":evtype", key) == 0) {
        i3_msg *msg = ctx->msg;
        if (msg) {
            sb_push(sb, get_eventtype(msg->type));
        } else {
            sb_pushn(sb, "none", 4);
        }
    } else if (strcmp(":nodei", key) == 0) {
        sb_pushf(sb, "%d", ctx->objcount);
    } else if (strcmp(":matchc", key) == 0) {
        sb_pushf(sb, "%d", ctx->matchcount);
    } else if (strncmp(":json", key, 5) == 0 && (key[5] == '\0' || key[5] == ':')) {
        yajl_val n = node;
        if (key[5]) {
            n = yajlutil_path_get(node, key + 6, yajl_t_any);
        }
        if (n) {
            yajlutil_serialize_val(get_sb_gen(ctx), n, 0);
        } else {
            sb_pushn(sb, "null", 4);
        }
    } else {
        yajl_val n = yajlutil_path_get(node, key, yajl_t_any);
        const char *str = yajlutil_get_string(n);
        if (str) {
            sb_push(sb, str);
        } else {
            // n is array or object
            yajlutil_serialize_val(get_sb_gen(ctx), n, 0);
        }
    }
}

static void format_fields(yajl_val node, iter_info *info, context *ctx, int match) {
    int i;
    string_builder *sb = &ctx->sb;
    if (match && ctx->flags & F_HIGHLIGHT) {
        sb_push(sb, COL_BOLD);
    }
    for (i = 0; i < ctx->outputc; i++) {
        if (i) sb_pushn(sb, ctx->field_sep, ctx->field_sep_len);
        const char *key = ctx->outputs[i];
        push_value(sb, key, node, info, ctx, match);
    }
    if (match && ctx->flags & F_HIGHLIGHT) {
        sb_push(sb, COL_NORMAL);
    }
}

static void accum_itree(iter_info *info, context *context) {
    sb_trunc(&context->itree, info->level);
    char ch = CH_SPACE;
    if (info->level && info->nodei < info->nodec - 1) {
        ch = CH_BAR;
    }
    sb_pushn(&context->itree, &ch, 1);
}

typedef struct node_getter_args {
    yajl_val node;
    iter_info *info;
    context *ctx;
} node_getter_args;

static const char *node_value_getter(const char *key, void *ptr) {
    node_getter_args *args = ptr;
    string_builder *sb = &args->ctx->sb;
    sb_trunc(sb, 0);
    push_value(sb, key, args->node, args->info, args->ctx, 1);
    return sb->buf;
}

static iter_advise process_node(yajl_val node, iter_info *info, context *ctx) {
    ++ctx->objcount;
    node_getter_args gargs = {
        .node = node,
        .info = info,
        .ctx = ctx,
    };
    int match = 0;
    if (i3json_matchers_match_ex(ctx->matcherc, ctx->matchers, &node_value_getter, &gargs)) {
        ++ctx->matchcount;
        match = 1;
    }
    accum_itree(info, ctx);
    if (match || ctx->flags & F_PRINTALL) {
        switch (ctx->outmode) {
        case OUT_NONE:
            break;
        case OUT_FIELDS:
            sb_trunc(&ctx->sb, 0);
            format_fields(node, info, ctx, match);
            sb_pushn(&ctx->sb, "\n", 1);
            fwrite(ctx->sb.buf, sizeof(char), ctx->sb.len, stdout);
            if (ctx->flags & F_FLUSH) {
                fflush(stdout);
            }
            break;
        }
    }
    if (match && ctx->maxcount > 0 && ctx->matchcount >= ctx->maxcount) {
        return ITER_ABORT_SUCCESS;
    }
    return ITER_CONT;
}

static iter_advise iter_pred(yajl_val node, iter_info *info, void *ptr) {
    context *ctx = ptr;
    i3json_tree_accum_data(node, info, &ctx->pt_context);
    return process_node(node, info, ctx);
}

static int eventloop(int sock, context *ctx) {
    i3_msg msg = EMPTY_I3_MSG;
    yajl_val event = NULL;
    char errbuf[ERROR_BUFSIZ];
    // iter_info values not meaningful for events
    iter_info info = { 0, 0, 0, 0, 0 };
    ctx->msg = &msg;
    int status = 0;
    for (;;) {
        if (i3ipc_recv_message(sock, &msg) == -1) {
            del_i3_msg(&msg);
            return 2;
        }
        event = yajl_tree_parse(msg.data, errbuf, sizeof(errbuf));
        if (!event) {
            print_error("parse error", errbuf);
        }
        iter_advise advise = process_node(event, &info, ctx);
        yajl_tree_free(event);
        i3ipc_msg_recycle(&msg);
        event = NULL;
        switch (advise) {
        case ITER_ABORT_SUCCESS:
            status = 0;
            goto cleanup;
        case ITER_ABORT:
            status = 1;
            goto cleanup;
        case ITER_CONT:
            break;
        case ITER_NODESC:
            assert(0);
        }
    }
cleanup:
    del_i3_msg(&msg);
    ctx->msg = NULL;
    return status;
}

static int match_evtype_only(i3json_matcher *matchers, int matcherc, const char *type) {
    int i;
    for (i = 0; i < matcherc; i++) {
        i3json_matcher *matcher = matchers + i;
        if (i3json_matcher_cmp_key(matcher, ":evtype") == 0) {
            if (!i3json_matcher_match_value(type, matcher)) {
                return 0;
            }
        }
    }
    return 1;
}

static char *get_matching_evtypes(i3json_matcher *matchers, int matcherc, int swaymode) {
    string_builder sb = EMPTY_STRING_BUILDER;
    yajl_gen gen = yajl_gen_alloc(NULL);
    malloc_check(gen);
    int res = yajl_gen_config(gen, yajl_gen_print_callback,
                              yajlutil_print_cb_sb_push, &sb);
    assert(res);
    int i;
    int matches = 0;
    yajl_gen_array_open(gen);
    for (i = 0; i < EVENT_TYPE_COUNT + EVENT_TYPE_SWAY_COUNT; i++) {
        if (swaymode) {
            // no output events on sway
            if (i == 1) continue;
        } else {
            // no sway events on i3
            if (i >= EVENT_TYPE_COUNT) break;
        }
        const char *name = i < EVENT_TYPE_COUNT ? EVENT_NAMES[i]
             : EVENT_NAMES_SWAY[i - EVENT_TYPE_COUNT];
        if (match_evtype_only(matchers, matcherc, name)) {
            ++matches;
            debug_print("%s matches\n", name);
            yajl_gen_string(gen, (const unsigned char *) name, strlen(name));
        }
    }
    yajl_gen_array_close(gen);
    yajl_gen_free(gen);
    if (!matches) {
        sb_free(&sb);
        return NULL;
    }
    return sb_disown(&sb);
}

int main(int argc, char *argv[]) {
    i3json_matcher matchers[argc];

    #define SMALL_ITREE_SIZE 16
    char itree[SMALL_ITREE_SIZE];
    context context = {
        .matchers = matchers,
        .matcherc = 0,
        .outmode = OUT_NONE,
        .outputs = NULL,
        .outputc = 0,
        .flags = 0,
        .maxcount = 0,
        .field_sep = " ",
        .field_sep_len = 1,
        .swaymode = 0,
        .sb = EMPTY_STRING_BUILDER,
        .itree = SB_WITH_EXT_BUF(itree, SMALL_ITREE_SIZE),
        .matchcount = 0,
        .pt_context = I3JSON_EMPTY_PRINT_TREE_CONTEXT,
        .sb_gen = NULL,
    };

    debug_print("BUFSIZ=%d\n", BUFSIZ);

    #define EXIT_MODE_ERROR(mode, option) \
        do { fprintf(stderr, option " can only be used in " mode "\n"); return 2; } while (0)
    const char *spath = NULL;
    mode mode = MODE_MATCH;
    int almostall = 0, mincount = 1, printtree = 0;
    char **aoutputs = NULL;
    int c;
    int have_modearg = 0;
    const char *infile = NULL;
    optind = 1;
    while (optind < argc) {
        int prevind = optind;
        if ((c = getopt(argc, argv, "+s:Si:ahml:n:d:e:toIW")) != -1) {
            debug_print("option: ind=%d c=%c\n", optind, c);
            switch (c) {
            case 's':
                spath = optarg;
                break;
            case 'S':
                if (have_modearg) {
                    fprintf(stderr, "cannot specify mode after mode-specific arguments\n");
                    return 2;
                }
                context.maxcount = 1;
                context.flags |= F_FLUSH;
                mode = MODE_SUBSCRIBE;
                break;
            case 'i':
                if (mode != MODE_MATCH) EXIT_MODE_ERROR("match-mode", "-i");
                have_modearg = 1;
                infile = optarg;
                break;
            case 'a':
                if (context.flags & F_PRINTALL) {
                    almostall = 1;
                }
                context.flags |= F_PRINTALL;
                break;
            case 'h':
                context.flags |= F_HIGHLIGHT;
                break;
            case 'm':
                if (mode != MODE_SUBSCRIBE) EXIT_MODE_ERROR("subscribe-mode", "-m");
                context.maxcount = -1;
                context.outmode = OUT_FIELDS;
                context.outputs = DEFAULT_MONITOR_OUTPUTS;
                context.outputc = DEFAULT_MONITOR_OUTPUT_COUNT;
                break;
            case 'l': {
                if (mode != MODE_MATCH) EXIT_MODE_ERROR("match-mode", "-l");
                int i, c;
                if (sscanf(optarg, "%d%n", &i, &c) < 1 || optarg[c] != 0) {
                    fprintf(stderr, "invalid min count (-l) - %s\n", optarg);
                    return 2;
                }
                have_modearg = 1;
                mincount = i;
                break;
            }
            case 'n': {
                int i, c;
                if (sscanf(optarg, "%d%n", &i, &c) < 1 || optarg[c] != 0) {
                    fprintf(stderr, "invalid max count (-n) - %s\n", optarg);
                    return 2;
                }
                have_modearg = 1;
                context.maxcount = i;
                break;
            }
            case 'd':
                context.field_sep = optarg;
                context.field_sep_len = strlen(optarg);
                break;
            case 'e': {
                have_modearg = 1;
                if (argc - optind < 2) {
                    fprintf(stderr, "missing %d arguments for -e\n", 2 + optind - argc);
                    return 2;
                }
                int op = i3json_parse_operator(argv[optind]);
                if (op == -1) {
                    fprintf(stderr, "invalid operator: %s\n", argv[optind]);
                    return 2;
                }
                i3json_make_matcher(optarg, argv[optind + 1], op, matchers + context.matcherc);
                ++context.matcherc;
                optind += 2;
                break;
            }
            case 't':
                if (mode != MODE_MATCH) EXIT_MODE_ERROR("match-mode", "-t");
                have_modearg = 1;
                printtree = 1;
                context.outmode = OUT_FIELDS;
                context.outputs = TREE_OUTPUTS;
                context.outputc = TREE_OUTPUTS_COUNT;
                break;
            case 'o':
                if (optind == prevind) {
                    fprintf(stderr, "no option allowed after -o\n");
                    return 2;
                }
                have_modearg = 1;
                context.outmode = OUT_FIELDS;
                if (printtree) {
                    aoutputs = calloc(argc - optind + 1, sizeof(char*));
                    malloc_check(aoutputs);
                    aoutputs[0] = ":itree";
                    memcpy(aoutputs + 1, argv + optind, (argc - optind) * sizeof(char*));
                    context.outputs = aoutputs;
                    context.outputc = argc - optind + 1;
                } else {
                    context.outputs = argv + optind;
                    context.outputc = argc - optind;
                }
                goto argparse_finished;
            case 'I':
                context.swaymode = 0;
                break;
            case 'W':
                context.swaymode = 1;
                break;
            case '?':
                return 2;
            default:
                assert(0);
            }
        } else {
            have_modearg = 1;
            const char *arg = argv[optind];
            if (i3json_parse_matcher(arg, matchers + context.matcherc) == -1) {
                fprintf(stderr, "invalid filter: %s\n", arg);
                return 2;
            }
            ++context.matcherc;
            ++optind;
        }
    }
argparse_finished: {}

    int result;

    switch (mode) {
    case MODE_MATCH: {
        if (context.outmode == OUT_NONE) {
            context.maxcount = mincount;
        }
        string_builder buf = EMPTY_STRING_BUILDER;
        i3_msg msg = EMPTY_I3_MSG;
        yajl_val tree = NULL;
        if (infile) {
            FILE *stream = NULL;
            FILE *f = NULL;
            if (strcmp(infile, "-") == 0) {
                stream = stdin;
            } else {
                f = stream = fopen(infile, "r");
                if (!f) {
                    perror("open");
                    return 2;
                }
            }
            push_whole_file(&buf, stream);
            if (ferror(stream)) {
                sb_free(&buf);
                if (f) fclose(f);
                return 2;
            }
            if (buf.len == 0) {
                fprintf(stderr, "json input is empty\n");
                if (f) fclose(f);
                return 2;
            }
            char errbuf[ERROR_BUFSIZ];
            tree = yajl_tree_parse(buf.buf, errbuf, sizeof(errbuf));
            if (!tree) {
                print_error("json error", errbuf);
                sb_free(&buf);
                if (f) fclose(f);
                return 2;
            }
            if (f) fclose(f);
        } else {
            set_default_sigchld_handler();
            int sock = i3ipc_open_socket(spath);
            if (sock == -1) {
                return 2;
            }
            if (i3util_request_json(sock, I3_IPC_MESSAGE_TYPE_GET_TREE, "", &msg, &tree) == -1) {
                close(sock);
                return 2;
            }
            debug_print("%s\n", "close sock...");
            close(sock);
        }
        i3json_iter_nodes(tree, &iter_pred, &context);
        yajl_tree_free(tree);
        del_i3_msg(&msg);
        sb_free(&buf);
        result = context.matchcount >= mincount ? 0 : 1;
        break;
    }
    case MODE_SUBSCRIBE: {
        set_default_sigchld_handler();
        int sock = i3ipc_open_socket(spath);
        if (sock == -1) {
            return 2;
        }
        {
            const char *body = NULL;
            char *astr = NULL;
            if (context.flags & F_PRINTALL && !almostall) {
                body = ALL_EVENTS_SUB_JSON_I3;
            } else {
                body = astr = get_matching_evtypes(
                     context.matchers, context.matcherc, context.swaymode);
                if (!body) {
                    fprintf(stderr, ":evtype never matches\n");
                    return 2;
                }
            }
            debug_print("body=%s\n", body);
            if (i3util_subscribe(sock, body) == -1) {
                fprintf(stderr, "subscribe request failed\n");
                free(astr);
                return 2;
            }
            free(astr);
        }
        result = eventloop(sock, &context);
        close(sock);
        break;
    }
    default:
        assert(0);
    }

    debug_print("%s\n", "cleanup...");
    if (context.sb_gen) {
        yajl_gen_free(context.sb_gen);
    }
    sb_free(&context.itree);
    sb_free(&context.sb);
    free(aoutputs);

    return result;
}
