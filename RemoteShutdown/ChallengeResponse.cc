#include "ChallengeResponse.h"

#include "sha256.h"

std::string CChallengeResponse::createChallange()
{
    std::unique_ptr<char> random(generateRandom(RANDOM_LEN));

    if (!random.get())
    {
        return "";
    }

    return sha256::ToHex(*sha256::Hash(std::vector<byte>(random.get(), random.get() + RANDOM_LEN)));
}

bool CChallengeResponse::verifyResponse(std::string &challange, std::string &secret, std::string &response)
{
	std::string working;

	working += challange;
	working += secret;

	std::string valid_response = NULL; // hash(working.c_str(), working.length());

	return (0 == valid_response.compare(response));
}


char *CChallengeResponse::generateRandom(unsigned int len)
{
	HCRYPTPROV hCryptProv;
	char *pRandom = new char[len];
	char *pReturn;

	// Acquire a cryptographic provider context handle
	if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0))
	{
		// try to catch error
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				return nullptr;
			}
		}
		else
		{
			return nullptr;
		}
	}

	// Generate the random number
	if (!CryptGenRandom(hCryptProv, len, (unsigned char*)pRandom))
	{
		pReturn = nullptr;
	}
	else
	{
		pReturn = pRandom;
	}

	CryptReleaseContext(hCryptProv, 0);

	return pReturn;
}