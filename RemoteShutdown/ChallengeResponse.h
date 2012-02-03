#pragma once
#pragma comment(lib, "crypt32.lib")
#define RANDOM_LEN 256

#include <string>
#include <windows.h>
#include <wincrypt.h>

#include "sha2.h"

class CChallengeResponse
{
  public:
    static std::string createChallange();
    static bool verifyResponse(std::string &challange, std::string &secret, std::string &response);

  private:
    static char *generateRandom(unsigned int len);
    static std::string hash(const char* input, unsigned int len);
};

