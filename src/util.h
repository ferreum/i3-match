
#ifndef _UTIL_H_
#define _UTIL_H_

#include "sb.h"

#include <stdio.h>

extern void set_default_sigchld_handler(void);

extern char *read_line(FILE *f);

extern int fork_exec(char **args);

extern int sleep_ms(int ms);

extern void push_whole_file(string_builder *sb, FILE *f);

extern void print_error(char *msg, char *errbuf);

#define STACK_SUBSTR(name, src, len) \
    char name[len + 1]; \
    strncpy(name, src, len); \
    name[len] = '\0';

#endif /* _UTIL_H_ */
