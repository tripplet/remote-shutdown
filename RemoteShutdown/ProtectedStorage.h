#pragma once

#pragma comment(lib, "crypt32.lib")

#include <string>
#include <memory>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

#include "RegHelper.h"

#define DEFAULT_REG_PATH "SOFTWARE\\"
#define DEFAULT_REG_ROOT HKEY_LOCAL_MACHINE

class ProtectedStorage
{
private:
	std::vector<byte> encrypt(std::string const &data) const;
	std::string decrypt(DATA_BLOB &data) const;

	std::string subkey;
	std::vector<byte> entropy;
	DATA_BLOB entropyObject;

public:
	ProtectedStorage(std::string const& storageName);
	ProtectedStorage(std::string const &storageName, std::string const &entropy);

	bool save(std::string const &key, std::string const &data) const;
	std::string read(std::string const &key) const;
};

