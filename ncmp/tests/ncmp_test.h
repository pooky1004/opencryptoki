/*
 * Token NCMP - Minimal test harness (header-only).
 *
 * Deliberately tiny so the suite stays dependency-free and runnable under
 * ctest. Each test file exposes int <name>(void) returning 0 on success.
 */
#ifndef NCMP_TEST_H
#define NCMP_TEST_H

#include <stdio.h>

#define NCMP_CHECK(cond)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                    #cond);                                               \
            return 1;                                                     \
        }                                                                 \
    } while (0)

#define NCMP_RUN(fn)                                                       \
    do {                                                                  \
        fprintf(stderr, "RUN  %s\n", #fn);                                \
        if ((fn)() != 0) {                                                \
            fprintf(stderr, "FAILED %s\n", #fn);                          \
            failures++;                                                   \
        } else {                                                         \
            fprintf(stderr, "PASS %s\n", #fn);                           \
        }                                                                 \
    } while (0)

#endif /* NCMP_TEST_H */
