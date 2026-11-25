#pragma once

#include <stddef.h>

#define REG_EXTENDED 0
#define REG_NOSUB 0

#define REG_NOMATCH 1
#define REG_BADPAT 2

typedef struct {} regex_t;
typedef struct {} regmatch_t;

static inline int regcomp(regex_t *preg, const char *regex, int cflags)
{
    return REG_BADPAT;
}

static inline int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
{
    return REG_NOMATCH;
}

static inline size_t regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
{
    return 0;
}

static inline void regfree(regex_t *preg)
{
}
