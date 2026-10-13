#include <string.h>

#include "parse.h"

#define CHECK(x) do { if (!(x)) return -1; } while (0)

static int scan(const char *buf, size_t n)
{
	char tmp[64];
	CHECK(n < sizeof tmp);
	memcpy(tmp, buf, n);
	return (int)n;
}

int parse(const char *buf, size_t n, struct handler *h)
{
	int r = scan(buf, n);
	if (r < 0)
		return r;
	return h->on_token(buf, n);
}
