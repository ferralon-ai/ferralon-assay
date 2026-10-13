#pragma once

#include <string>

namespace codec {

class Decoder {
public:
	virtual ~Decoder() = default;
	virtual int decode(const std::string &in) = 0;
};

class Inflate : public Decoder {
public:
	int decode(const std::string &in) override;
	int window() const;
};

int checksum(const std::string &in);

} // namespace codec
