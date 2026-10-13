#include <iostream>

#include "codec.hpp"

static int run(codec::Decoder &d, const std::string &in)
{
	return d.decode(in);
}

int main(int argc, char **argv)
{
	codec::Inflate inf;
	std::string in = argc > 1 ? argv[1] : "";
	std::cout << run(inf, in) << std::endl;
	return codec::checksum(in) > 0 ? 0 : 1;
}
