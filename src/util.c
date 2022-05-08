
#include "util.h"
#include "base.h"
#include "debug.h"

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

static void signal_child(__unused int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

extern void set_default_sigchld_handler(void) {
    signal(SIGCHLD, &signal_child);
}

extern char *read_line(FILE *f) {
    char buf[BUFSIZ];
    int len = 0;
    char *line = NULL;
    while (!feof(f) && !ferror(f) && fgets(buf, BUFSIZ, f)) {
        size_t l = strlen(buf);
        if (buf[l-1] == '\n') {
            l -= 1;
        }
        line = realloc(line, len + l + 1);
        malloc_check(line);
        strncpy(line + len, buf, l);
        len += l;
        if (l < BUFSIZ-1) {
            break;
        }
    }
    if (line) line[len] = '\0';
    return line;
}

extern void push_whole_file(string_builder *sb, FILE *f) {
    char buf[BUFSIZ];
    size_t n;
    while (!ferror(f) && !feof(f)) {
        n = fread(buf, sizeof(char), BUFSIZ, f);
        if (n > 0) {
            sb_pushn(sb, buf, n);
        }
    }
}

extern void print_error(char *errmsg, char *errbuf) {
    fprintf(stderr, "%s: ", errmsg);
    if (errbuf[0]) fprintf(stderr, "%s", errbuf);
    else fprintf(stderr, "unknown error\n");
}

