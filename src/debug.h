
#ifndef _F__DEBUG_H_
#define _F__DEBUG_H_

#ifndef DEBUG
#define DEBUG 0
#endif

#define debug_print(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#endif /* _f__DEBUG_H_ */
