#include "sha256.h"

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#include <sstream>
#include <iomanip>

#define STATUS_SUCCESS ((NTSTATUS)0)

namespace sha256
{

    bool constant_time_compare(const void *a, const void *b, const size_t size)
    {
        if (a == nullptr || b == nullptr)
        {
            return false;
        }

        auto _a = reinterpret_cast<const unsigned char*>(a);
        auto _b = reinterpret_cast<const unsigned char*>(b);

        unsigned char result = 0;
        for (size_t i = 0; i < size; i++)
        {
            result |= _a[i] ^ _b[i];
        }

        return result == 0;
    }

    std::string ToHex(std::vector<byte> const &data)
    {
        std::stringstream hashString;
        for each (const int value in data)
        {
            hashString << std::setfill('0') << std::setw(2) << std::hex << value;
        }

        return hashString.str();
    }

    std::shared_ptr<std::vector<byte>> Hash(std::string const &message)
    {
        return Hash(std::vector<byte>(message.begin(), message.end()));
    }

    std::shared_ptr<std::vector<byte>> Hash(std::vector<byte> const &message)
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

        NTSTATUS status = -1;
        DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

        std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

        try
        {
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Calculate the sizes
            status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&sizeHashObject), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&sizeHash), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
            std::unique_ptr<byte> hashObject(new byte[sizeHashObject]);

            // Create the hash
            status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.get(), sizeHashObject, nullptr, 0U, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Hash the data
            status = BCryptHashData(hHash, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Finish the hash
            status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }
        }
        catch (...)
        {
        }

        if (hHash) { BCryptDestroyHash(hHash); }
        if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0U); }

        if (status == STATUS_SUCCESS)
        {
            return hashBytes;
        }
        else
        {
            return nullptr;
        }
    }

    std::shared_ptr<std::vector<byte>> HashHMAC(std::string const &key, std::string const &message)
    {
        return HashHMAC(std::vector<byte>(key.begin(), key.end()), std::vector<byte>(message.begin(), message.end()));
    }

    // https://stackoverflow.com/questions/22147895/is-it-possible-to-do-a-hmac-with-wincrypt/22155681#22155681
    // https://docs.microsoft.com/de-de/windows/desktop/SecCNG/creating-a-hash-with-cng
    std::shared_ptr<std::vector<byte>> HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message)
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

        NTSTATUS status = -1;
        DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

        std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

        try
        {
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Calculate the sizes
            status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&sizeHashObject), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&sizeHash), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
            std::unique_ptr<byte> hashObject(new byte[sizeHashObject]);

            // Create the hash
            status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.get(), sizeHashObject, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Hash the data
            status = BCryptHashData(hHash, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }

            // Finish the hash
            status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0U);
            if (status != STATUS_SUCCESS)
            {
                throw 0;
            }
        }
        catch (...)
        {
        }

        // Cleanup
        if (hHash) { BCryptDestroyHash(hHash); }
        if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0U); }

        if (status != STATUS_SUCCESS)
        {
            return nullptr;
        }
        else
        {
            return hashBytes;
        }
    }

} // end of namespace
