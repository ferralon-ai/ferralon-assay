#include "codec.hpp"

namespace codec {

int checksum(const std::string &in)
{
	int sum = 0;
	for (char c : in)
		sum += c;
	return sum;
}

int Inflate::window() const
{
	return 15;
}

int Inflate::decode(const std::string &in)
{
	return checksum(in) + window();
}

} // namespace codec
