#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <memory>

class sha256
{
public:
	static std::shared_ptr<std::vector<byte>> sha256::Hash(std::string const &message);
	static std::shared_ptr<std::vector<byte>> sha256::Hash(std::vector<byte> const &message);

	static std::shared_ptr<std::vector<byte>> sha256::HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message);
	static std::shared_ptr<std::vector<byte>> sha256::HashHMAC(std::string const &key, std::string const &message);

	static std::string sha256::ToHex(std::vector<byte> const &data);

private:
	static bool constant_time_compare(const void *a, const void *b, const size_t size);
};

