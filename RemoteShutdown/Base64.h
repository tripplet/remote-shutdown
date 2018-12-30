#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace base64
{
    std::basic_string<TCHAR> Encode(std::vector<byte> inputBuffer);
    std::vector<byte> Decode(const std::basic_string<TCHAR>& input);
}