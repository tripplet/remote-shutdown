#include "ChallengeResponse.h"

#include "sha256.h"

#define RANDOM_LEN 4096

const std::string CChallengeResponse::createChallange()
{
    auto random = generateRandom(RANDOM_LEN);
    if (!random)
    {
        return "";
    }

    return sha256::ToHex(*sha256::Hash(*random.get()));
}

bool CChallengeResponse::verifyResponse(std::string const &challenge, std::string const &secret, std::string const &response)
{
    const auto index = response.find(".");
    if (index == std::string::npos)
    {
        return false;
    }

    const auto command = response.substr(0U, index);
    auto valid_response = sha256::ToHex(*sha256::HashHMAC(secret, command + "." + challenge));

    return (sha256::constant_time_compare(command + "." + valid_response, response));
}


std::unique_ptr<std::vector<byte> const> CChallengeResponse::generateRandom(unsigned int len)
{
    HCRYPTPROV hCryptProv = 0;
	auto random = std::make_unique<std::vector<byte>>(len);

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
	const auto success = CryptGenRandom(hCryptProv, len, random.get()->data());
	CryptReleaseContext(hCryptProv, 0);
	
	if (success)
    {
		return random;
    }
	else
	{
		return nullptr;
	}
}