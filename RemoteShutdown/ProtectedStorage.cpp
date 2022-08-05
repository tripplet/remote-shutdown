#include "ProtectedStorage.h"

ProtectedStorage::ProtectedStorage(std::string const& storageName)
{
    ProtectedStorage(storageName, std::string());
}

ProtectedStorage::ProtectedStorage(std::string const &storageName, std::string const &entropy)
{
    this->subkey = DEFAULT_REG_PATH + storageName;

    if (entropy.size() > 0) 
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
    return registry::SetKeyValue(DEFAULT_REG_ROOT, subkey.c_str(), key.c_str(), encryptedData->pbData, static_cast<int>(encryptedData->cbData));
}

std::string ProtectedStorage::read(std::string const& key) const
{
    bool success = false;
    unsigned long size = 0;
    DATA_BLOB input = {};

    input.pbData = registry::GetKeyData(DEFAULT_REG_ROOT, subkey.c_str(), key.c_str(), success, size);

    if (success)
    {
        input.cbData = static_cast<DWORD>(size);
        auto returnValue = decrypt(input);

        delete[] input.pbData;

        return returnValue;
    }
    else
    {
        return "";
    }
}


std::unique_ptr<DATA_BLOB> ProtectedStorage::encrypt(std::string const& data) const
{
    auto output = std::make_unique<DATA_BLOB>();
    DATA_BLOB input = {};

    output->cbData = 0;
    input.pbData = (BYTE*)data.c_str();
    input.cbData = (DWORD)data.length() + 1;

    DATA_BLOB* entropy = nullptr;
    if (this->entropyObject.cbData > 0)
    {
        entropy = const_cast<DATA_BLOB*>(&this->entropyObject);
    }

    CryptProtectData(&input, nullptr, entropy, nullptr, nullptr, 0, output.get());

    return output;
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