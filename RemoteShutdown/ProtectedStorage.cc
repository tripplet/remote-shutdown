#include "ProtectedStorage.h"


ProtectedStorage::ProtectedStorage(std::string const &storageName) : entropy(nullptr)
{
	this->subkey = DEFAULT_REG_PATH + storageName;
}

ProtectedStorage::ProtectedStorage(std::string const &storageName, std::string const &entropy)
{
	this->subkey = DEFAULT_REG_PATH + storageName;

	this->entropy = new DATA_BLOB;
	BYTE* data = new BYTE[this->entropy->cbData];

	this->entropy->pbData = new BYTE[this->entropy->cbData];
	this->entropy->cbData = (DWORD)entropy.length();

	memcpy_s(this->entropy->pbData, sizeof(BYTE), entropy.data(), this->entropy->cbData);
}


ProtectedStorage::~ProtectedStorage()
{
	if (this->entropy != nullptr)
	{
		delete[] this->entropy->pbData;
	}

	delete this->entropy;
	this->entropy = nullptr;
}


bool ProtectedStorage::save(std::string const &key, std::string const &data)
{
	DATA_BLOB* encryptedData = encrypt(data);
	bool ret = registry::SetKeyValue(DEFAULT_REG_ROOT, subkey.c_str(), key.c_str(), encryptedData->pbData, static_cast<int>(encryptedData->cbData));

	LocalFree(encryptedData->pbData);
	delete encryptedData;

	return ret;
}

std::string ProtectedStorage::read(std::string const &key)
{
	bool success = false;
	unsigned long size = 0;
	DATA_BLOB input;

	input.pbData = registry::GetKeyData(DEFAULT_REG_ROOT, subkey.c_str(), key.c_str(), success, size);

	if (success)
    {
		input.cbData = static_cast<int>(size);
		std::string returnValue = decrypt(input);

		delete[] input.pbData;

		return returnValue;
	}
	else
	{
		return "";
	}
}


DATA_BLOB* ProtectedStorage::encrypt(std::string const &data)
{
	DATA_BLOB* output = new DATA_BLOB;
	DATA_BLOB input;

	output->cbData = 0;
	input.pbData = (BYTE*)data.data();
	input.cbData = (DWORD)data.length() + 1;

	CryptProtectData(&input, nullptr, (DATA_BLOB*) this->entropy, nullptr, nullptr, 0, output);

	return output;
}

std::string ProtectedStorage::decrypt(DATA_BLOB const &data)
{
	DATA_BLOB output;
	std::string str_output;

	if (CryptUnprotectData((DATA_BLOB*) &data, nullptr, (DATA_BLOB*) this->entropy, nullptr, nullptr, 0, &output))
	{
		str_output = (char*)output.pbData;
		LocalFree(output.pbData);

		return str_output;
	}
	else
	{
		return std::string("");
	}
}