#include "parse.h"

static int count(const char *tok, size_t n)
{
	(void)tok;
	return (int)n;
}

int apply(const char *buf, size_t n)
{
	struct handler h = { count };
	return parse(buf, n, &h);
}

int unused_export(void)
{
	return 0;
}
