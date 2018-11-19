#include "sha256.h"

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#include <sstream>
#include <iomanip>

#define STATUS_SUCCESS ((NTSTATUS)0)

#pragma comment(lib, "bcrypt.lib")

bool sha256::constant_time_compare(const void *a, const void *b, const size_t size)
{
	const unsigned char *_a = (const unsigned char *)a;
	const unsigned char *_b = (const unsigned char *)b;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		result |= _a[i] ^ _b[i];
	}

	return result == 0;
}

std::string sha256::ToHex(std::vector<byte> const &data)
{
	std::stringstream hashString;
	for each (int value in data)
	{
		hashString << std::setfill('0') << std::setw(2) << std::hex << value;
	}

	return hashString.str();
}

std::shared_ptr<std::vector<byte>> sha256::Hash(std::string const &message)
{
	return sha256::Hash(std::vector<byte>(message.begin(), message.end()));
}

std::shared_ptr<std::vector<byte>> sha256::Hash(std::vector<byte> const &message)
{
	BCRYPT_HASH_HANDLE hHash = nullptr;
	BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

	NTSTATUS status = -1;
	DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

	std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

	try
	{
		status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Calculate the sizes
		status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&sizeHashObject, sizeof(DWORD), &sizeData, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&sizeHash, sizeof(DWORD), &sizeData, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
		std::unique_ptr<byte> hashObject(new byte[sizeHashObject]);

		// Create the hash
		status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.get(), sizeHashObject, NULL, 0, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Hash the data
		status = BCryptHashData(hHash, (PUCHAR)message.data(), (ULONG)message.size(), 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Finish the hash
		status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}
	}
	catch (const std::exception)
	{
	}

	if (hAlgorithm)
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (status != STATUS_SUCCESS)
	{
		return nullptr;
	}
	else
	{
		return hashBytes;
	}
}

std::shared_ptr<std::vector<byte>> sha256::HashHMAC(std::string const &key, std::string const &message)
{
	return sha256::HashHMAC(std::vector<byte>(key.begin(), key.end()), std::vector<byte>(message.begin(), message.end()));
}

// https://stackoverflow.com/questions/22147895/is-it-possible-to-do-a-hmac-with-wincrypt/22155681#22155681
// https://docs.microsoft.com/de-de/windows/desktop/SecCNG/creating-a-hash-with-cng
std::shared_ptr<std::vector<byte>> sha256::HashHMAC(std::vector<byte> const &key, std::vector<byte> const &message)
{
	BCRYPT_HASH_HANDLE hHash = nullptr;
	BCRYPT_ALG_HANDLE hAlgorithm = nullptr;

	NTSTATUS status = -1;
	DWORD sizeHashObject = 0, sizeHash = 0, sizeData = 0;

	std::shared_ptr<std::vector<byte>> hashBytes = nullptr;

	try
	{
		status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Calculate the sizes
		status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&sizeHashObject, sizeof(DWORD), &sizeData, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&sizeHash, sizeof(DWORD), &sizeData, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		auto hashBytes = std::make_shared<std::vector<byte>>(sizeHash);
		std::unique_ptr<byte> hashObject(new byte[sizeHashObject]);

		// Create the hash
		status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.get(), sizeHashObject, (PUCHAR)key.data(), (ULONG)key.size(), 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Hash the data
		status = BCryptHashData(hHash, (PUCHAR)message.data(), (ULONG)message.size(), 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		// Finish the hash
		status = BCryptFinishHash(hHash, hashBytes.get()->data(), sizeHash, 0);
		if (status != STATUS_SUCCESS)
		{
			throw;
		}

		if (hAlgorithm)
		{
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		}

		if (hAlgorithm)
		{
			BCryptDestroyHash(hHash);
		}

		return hashBytes;
	}
	catch (const std::exception)
	{
	}

	if (hAlgorithm)
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (status != STATUS_SUCCESS)
	{
		return nullptr;
	}
	else
	{
		return hashBytes;
	}
}
