#include "sha256.h"

#include <windows.h>
#include <bcrypt.h>

#include <sstream>
#include <iomanip>

#define STATUS_SUCCESS ((NTSTATUS)0)

namespace sha256
{
    const std::string GetLastErrorMessage();

    bool constant_time_compare(std::string const &value1, std::string const &value2)
    {
        if (value1.size() != value2.size() || value1.size() == 0)
        {
            return false;
        }

        bool result = true;
        for (size_t i = 0; i < value1.size(); i++)
        {
            result &= value1.at(i) == value2.at(i);
        }

        return result;
    }

    /**
     * Converts the given byte array to a hex string
     * @param data The byte array
     * @return The hex string
     */
    const std::string ToHex(std::vector<byte> const &byteArray)
    {
        std::stringstream hashString;
        for each (const int value in byteArray)
        {
            hashString << std::setfill('0') << std::setw(2) << std::hex << value;
        }

        return hashString.str();
    }

    /**
     * Generate a sha265 hash from the message
     * @param message The message
     * @return The sha265 hash as byte array
     */
    std::shared_ptr<std::vector<byte> const> Hash(std::string const &message)
    {
        return Hash(std::vector<byte>(message.begin(), message.end()));
    }

    /**
     * Generate a sha265 hash from the message
     * @param message The message
     * @return The sha265 hash as byte array
     */
    std::shared_ptr<std::vector<byte> const> Hash(std::vector<byte> const &message)
    {
        std::string errorMessage;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

        NTSTATUS status = -1;
        DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

        std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

        try
        {
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Calculate the sizes
            status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&sizeHashObject), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&sizeHash), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
            auto hashObject = std::vector<byte>(sizeHashObject);

            // Create the hash
            status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.data(), sizeHashObject, nullptr, 0U, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Hash the data
            status = BCryptHashData(hHash, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Finish the hash
            status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }
        }
        catch (...)
        {
            errorMessage = GetLastErrorMessage();
        }

        if (hHash) { BCryptDestroyHash(hHash); }
        if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0U); }

        if (status == STATUS_SUCCESS)
        {
            return hashBytes;
        }
        else
        {
            throw std::logic_error(errorMessage);
        }
    }

    /**
     * Generate a sha265 based HMAC from the message and the given key
     * @param key The key to use
     * @param message The message
     * @return The sha265 HMAC
     */
    std::shared_ptr<std::vector<byte> const> HashHMAC(std::string const &key, std::string const &message)
    {
        return HashHMAC(std::vector<byte>(key.begin(), key.end()), std::vector<byte>(message.begin(), message.end()));
    }

    /**
     * Generate a sha265 based HMAC from the message and the given key
     * @param key The key to use
     * @param message The message
     * @return The sha265 HMAC
     */
    std::shared_ptr<std::vector<byte> const> HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message)
    {
        // https://stackoverflow.com/questions/22147895/is-it-possible-to-do-a-hmac-with-wincrypt/22155681#22155681
        // https://docs.microsoft.com/de-de/windows/desktop/SecCNG/creating-a-hash-with-cng
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

        std::string errorMessage;
        NTSTATUS status = -1;
        DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

        std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

        try
        {
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Calculate the sizes
            status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&sizeHashObject), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&sizeHash), sizeof(DWORD), &sizeData, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
            auto hashObject = std::vector<byte>(sizeHashObject);

            // Create the hash
            status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.data(), sizeHashObject, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Hash the data
            status = BCryptHashData(hHash, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), 0U);
            if (status != STATUS_SUCCESS) { throw 0; }

            // Finish the hash
            status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0U);
            if (status != STATUS_SUCCESS) { throw 0; }
        }
        catch (...)
        {
            errorMessage = GetLastErrorMessage();
        }

        // Cleanup
        if (hHash) { BCryptDestroyHash(hHash); }
        if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0U); }

        if (status == STATUS_SUCCESS)
        {
            return hashBytes;
        }
        else
        {
            throw std::logic_error(errorMessage);
        }
    }

    /**
     * Retrieve the system error message for the last-error code
     * @return String error message for the last-error code
     */
    const std::string GetLastErrorMessage()
    {
        // Retrieve the system error message for the last-error code
        const auto lastError = GetLastError();

        if (lastError == 0)
        {
            return "No Error";
        }

        void* errorString = nullptr;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            lastError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPTSTR>(&errorString),
            0U, nullptr);

        if (errorString == nullptr)
        {
            return "Error creating error message";
        }

        std::stringstream errorMessage;
        errorMessage << "Error " << lastError << ": " << static_cast<LPTSTR>(errorString);

        LocalFree(errorString);
        return errorMessage.str();
    }
} // end of namespace
