#include <string.h>

#include "parse.h"

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;
	return apply(argv[1], strlen(argv[1]));
}
