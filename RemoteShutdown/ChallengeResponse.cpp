#include "ChallengeResponse.h"

std::string CChallengeResponse::createChallange() {
  char *pRandom = generateRandom(RANDOM_LEN);

  if (!pRandom)
    return std::string("");

  std::string secret = hash(pRandom,RANDOM_LEN);
  delete[] pRandom;

  return secret;
}

bool CChallengeResponse::verifyResponse(std::string &challange, std::string &secret, std::string &response) {
  std::string working;

  working += challange;
  working += secret;

  std::string valid_response = hash(working.c_str(),working.length());

  return (0==valid_response.compare(response));
}


char *CChallengeResponse::generateRandom(unsigned int len)
{
  HCRYPTPROV hCryptProv;
  char *pRandom = new char[len];
  char *pReturn;

  // Acquire a cryptographic provider context handle
  if(!CryptAcquireContext(&hCryptProv,  NULL, NULL, PROV_RSA_FULL, 0)) 
    return NULL;

  // Generate the random number
  if(!CryptGenRandom(hCryptProv, len, (unsigned char*) pRandom))
    pReturn = NULL;
  else
    pReturn = pRandom;

  CryptReleaseContext(hCryptProv,0);

  return pReturn;
}

std::string CChallengeResponse::hash(const char* input, unsigned int len) {
	std::string tempHash;
	char tmp[3];
	unsigned char pHash[256];

  sha256_ctx m_sha256;

  sha256_begin(&m_sha256);
  sha256_hash((unsigned char *)input, len, &m_sha256);
  sha256_end(pHash, &m_sha256);

	for(int i = 0; i < 32; i++) {				
		_itoa(pHash[i], tmp , 16);
				
		if (strlen(tmp) == 1)
		{
			tmp[1] = tmp[0];
			tmp[0] = '0';
			tmp[2] = '\0';
		}

		tempHash += tmp;
	}

  return tempHash;
}