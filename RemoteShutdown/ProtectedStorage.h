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
	DATA_BLOB* encrypt(std::string &data);
	std::string decrypt(DATA_BLOB &data);

	std::string subkey;
	DATA_BLOB *entropy;

public:
	ProtectedStorage(std::string &storageName);
	ProtectedStorage(std::string &storageName, std::string &entropy);
	~ProtectedStorage();

	bool save(std::string &key, std::string &data);
	std::string read(std::string &key);
};

