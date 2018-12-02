#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <memory>

namespace sha256
{
	std::shared_ptr<std::vector<byte>> Hash(std::string const &message);
	std::shared_ptr<std::vector<byte>> Hash(std::vector<byte> const &message);

	std::shared_ptr<std::vector<byte>> HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message);
	std::shared_ptr<std::vector<byte>> HashHMAC(std::string const &key, std::string const &message);

	std::string ToHex(std::vector<byte> const &data);

	bool constant_time_compare(const void *a, const void *b, const size_t size);
};

