#include "ProtectedStorage.h"

ProtectedStorage::ProtectedStorage(std::string const& storageName)
    : ProtectedStorage(storageName, std::string())
{    
}

ProtectedStorage::ProtectedStorage(std::string const &storageName, std::string const &entropy)
{
    this->subkey = DEFAULT_REG_PATH + storageName;

    if (!entropy.empty()) 
    {
        this->entropy.assign(entropy.begin(), entropy.end());
        this->entropyObject.cbData = static_cast<DWORD>(this->entropy.size());
        this->entropyObject.pbData = this->entropy.data();
    }
    else
    {
        this->entropy = {};
        this->entropyObject.cbData = 0;
        this->entropyObject.pbData = nullptr;
    }
}

bool ProtectedStorage::save(std::string const &key, std::string const &data) const
{
    auto encryptedData = this->encrypt(data);
    return registry::SetKeyValue(DEFAULT_REG_ROOT, this->subkey.c_str(), key.c_str(), encryptedData.data(), static_cast<unsigned long>(encryptedData.size()));
}

std::string ProtectedStorage::read(std::string const& key) const
{
    bool success = false;
    unsigned long size = 0;
    DATA_BLOB input = {};

    input.pbData = registry::GetKeyData(DEFAULT_REG_ROOT, this->subkey.c_str(), key.c_str(), success, size);

    if (success)
    {
        input.cbData = static_cast<DWORD>(size);
        auto returnValue = decrypt(input);

        delete[] input.pbData;

        return returnValue;
    }
    else
    {
        return std::string();
    }
}

std::vector<byte> ProtectedStorage::encrypt(std::string const& data) const
{
    DATA_BLOB input = {};
    input.pbData = (BYTE*)data.c_str();
    input.cbData = (DWORD)data.length() + 1;

    DATA_BLOB* entropy = nullptr;
    if (this->entropyObject.cbData != 0)
    {
        entropy = const_cast<DATA_BLOB*>(&this->entropyObject);
    }

    std::vector<byte> encryptedData;
    DATA_BLOB output = {};
    auto result = CryptProtectData(&input, nullptr, entropy, nullptr, nullptr, 0, &output);
    if (!result)
    {
        encryptedData = std::vector<byte>();
    }
    else 
    {
        encryptedData = std::vector<byte>(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
    }

    return encryptedData;
}

std::string ProtectedStorage::decrypt(DATA_BLOB &data) const
{
    DATA_BLOB* entropy = nullptr;
    if (this->entropyObject.cbData > 0) 
    {
        entropy = const_cast<DATA_BLOB*>(&this->entropyObject);
    }

    std::string str_output;
    DATA_BLOB output;
    if (CryptUnprotectData(&data, nullptr, entropy, nullptr, nullptr, 0, &output))
    {
        str_output.assign((char*)output.pbData);
        LocalFree(output.pbData);

        return str_output;
    }
    else
    {
        return std::string();
    }
}