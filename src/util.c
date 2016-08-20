
#include "util.h"
#include "base.h"
#include "debug.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>
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
        strncpy(line + len, buf, l);
        len += l;
        if (l < BUFSIZ-1) {
            break;
        }
    }
    if (line) line[len] = '\0';
    return line;
}

extern int fork_exec(char **args) {
    switch (fork()) {
    case -1:
        // failed
        perror("fork");
        return -1;
    case 0: {
        if (execvp(args[0], args) == -1) {
            perror("execvp");
        }
        fprintf(stderr, "execvp failed");
        exit(1);
    }
    default:
        return 0;
    }
    assert(0);
}

extern int sleep_ms(int ms) {
    struct timespec tp;
    tp.tv_sec = ms / 1000;
    tp.tv_nsec = (ms % 1000) * 1000000;
    return nanosleep(&tp, NULL);
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

