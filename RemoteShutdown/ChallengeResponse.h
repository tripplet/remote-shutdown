#pragma once
#define RANDOM_LEN 256

#include <string>
#include <windows.h>
#include <memory>

class CChallengeResponse
{
  public:
    static std::string createChallange();
    static bool verifyResponse(std::string const &challange, std::string const &secret, std::string const &response);

  private:
    static char *generateRandom(unsigned int len);
    static std::string hash(const char* input, unsigned int len);
};

