#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <memory>

class CChallengeResponse
{
private:
    static std::vector<byte> generateRandom(unsigned int len);
    static INT64 GetCurrentTimestamp();
    static const std::string GetChallengeSecret();

public:
    static const std::string createSecret();
    static const std::string createChallenge();
    static bool verifyResponse(std::string const &requestSecret, std::string const &response);
};
