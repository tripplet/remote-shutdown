#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <memory>

namespace sha256
{
    std::shared_ptr<std::vector<byte> const> Hash(std::string const &message);
    std::shared_ptr<std::vector<byte> const> Hash(std::vector<byte> const &message);

    std::shared_ptr<std::vector<byte> const> HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message);
    std::shared_ptr<std::vector<byte> const> HashHMAC(std::string const &key, std::string const &message);

    const std::string ToHex(std::vector<byte> const &data);

    bool constant_time_compare(std::string const &value1, std::string const &value2);
};
