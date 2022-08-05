#include <ctime>
#include <stdexcept>

#include "GlobalConst.h"
#include "ChallengeResponse.h"

#include "sha256.h"

#define RANDOM_LEN 4096


/**
 * Generate a new challenge secret (constant while program is running)
 * @returns The challenge secret
 */
const std::string CChallengeResponse::GetChallengeSecret() 
{
    static std::string challengeSecret;

    if (challengeSecret.empty())
    {
        challengeSecret = CChallengeResponse::createSecret();
    }

    return challengeSecret;
}

const std::string CChallengeResponse::createSecret()
{
    return sha256::ToHex(*sha256::Hash(generateRandom(RANDOM_LEN)));
}

/// <summary>
/// Creates a signed challenge based on the given secret.
/// </summary>
/// <param name="secret">The secret.</param>
/// <returns>A signed challenge.</returns>
const std::string CChallengeResponse::createChallenge()
{
    auto rawChallenge = std::to_string(GetCurrentTimestamp() + RESPONSE_LIMIT);

    // create HMAC'ed challenge
    return rawChallenge + "." + sha256::ToHex(*sha256::HashHMAC(CChallengeResponse::GetChallengeSecret(), rawChallenge));
}

bool CChallengeResponse::verifyResponse(std::string const &requestSecret, std::string const &response)
{
    const auto index1 = response.find(".");
    if (index1 == std::string::npos)
    {
        return false;
    }

    const auto index2 = response.find(".", index1 + 1);
    if (index2 == std::string::npos)
    {
        return false;
    }

    const auto index3 = response.find(".", index2 + 1);
    if (index3 == std::string::npos)
    {
        return false;
    }

    const auto command = response.substr(0U, index1);
    const auto valid_until = response.substr(index1 + 1, index2 - index1 - 1);
    const auto challenge = response.substr(index2 + 1, index3 - index2 - 1);
    const auto hmac = response.substr(index3 + 1);

    if (command.empty() || valid_until.empty() || challenge.empty() || hmac.empty())
    {
        return false;
    }

    INT64 response_valid_until = 0;
    try {
        response_valid_until = std::stoll(valid_until);
    }
    catch (...)
    {
        return false;
    }

    if (response_valid_until < GetCurrentTimestamp())
    {
        return false;
    }

    // Verify the challenge is valid
    auto valid_challenge = sha256::ToHex(*sha256::HashHMAC(CChallengeResponse::GetChallengeSecret(), valid_until));
    if (!sha256::constant_time_compare(valid_challenge, challenge)) {
        return false;
    }

    // Verify the complete request
    auto valid_hmac = sha256::ToHex(*sha256::HashHMAC(requestSecret, command + "." + valid_until + "." + challenge));
    return (sha256::constant_time_compare(valid_hmac, hmac));
}

std::vector<byte> CChallengeResponse::generateRandom(unsigned int len)
{
    HCRYPTPROV hCryptProv = 0;
    auto random = std::vector<byte>(len);

    // Acquire a cryptographic provider context handle
    if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0))
    {
        // try to catch error
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            {
                throw std::logic_error("Unable to acquire crypt context for generating random data");
            }
        }
        else
        {
            throw std::logic_error("Unable to acquire crypt context for generating random data second time");
        }
    }

    // Generate the random number
    const auto success = CryptGenRandom(hCryptProv, len, random.data());
    CryptReleaseContext(hCryptProv, 0);

    if (success)
    {
        return random;
    }
    else
    {
        throw std::logic_error("Unable to generate random data");
    }
}

INT64 CChallengeResponse::GetCurrentTimestamp()
{
    const auto currentTime = std::time(nullptr);
    tm utcTime;
    gmtime_s(&utcTime, &currentTime);

    const auto utcTimestamp = std::mktime(&utcTime);

    return (INT64)utcTimestamp;
}