#pragma once

#pragma comment(lib, "crypt32.lib")

#include <string>
#include <windows.h>
#include <wincrypt.h>

#include "RegHelper.h"

#define DEFAULT_REG_PATH "SOFTWARE\\"
#define DEFAULT_REG_ROOT HKEY_LOCAL_MACHINE

class ProtectedStorage
{
private:
	DATA_BLOB* encrypt(std::string const &data);
	std::string decrypt(DATA_BLOB const &data);

	std::string subkey;
	DATA_BLOB *entropy;

public:
	ProtectedStorage(std::string const &storageName);
	ProtectedStorage(std::string const &storageName, std::string const &entropy);
	~ProtectedStorage();

	bool save(std::string const &key, std::string const &data);
	std::string read(std::string const &key);
};

