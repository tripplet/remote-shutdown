#pragma once
#define RANDOM_LEN 256

#include <string>
#include <windows.h>
#include <memory>

class CChallengeResponse
{
private:
    static char *generateRandom(unsigned int len);

public:
    static const std::string createChallange();
    static bool verifyResponse(std::string const &challange, std::string const &secret, std::string const &response);

};

