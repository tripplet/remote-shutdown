#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <memory>

class CChallengeResponse
{
private:
    static std::unique_ptr<std::vector<byte> const> generateRandom(unsigned int len);
    static INT64 GetCurrentTimestamp();

public:
    static const std::string createSecret();
    static const std::string createChallange();
    static bool verifyResponse(std::string const &secret, std::string const &response);

};
