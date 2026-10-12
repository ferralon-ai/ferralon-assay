#ifndef PARSE_H
#define PARSE_H

#include <stddef.h>

struct handler {
	int (*on_token)(const char *tok, size_t n);
};

int parse(const char *buf, size_t n, struct handler *h);
int apply(const char *buf, size_t n);

#endif
