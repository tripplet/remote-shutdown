#include "ProtectedStorage.h"


ProtectedStorage::ProtectedStorage(std::string &storageName) : entropy(NULL)
{
  this->subkey = DEFAULT_REG_PATH + storageName;
}

ProtectedStorage::ProtectedStorage(std::string &storageName, std::string &entropy)
{
  this->subkey = DEFAULT_REG_PATH + storageName;

  this->entropy = new DATA_BLOB;
  BYTE* data = new BYTE[this->entropy->cbData];
    
  this->entropy->pbData = new BYTE[this->entropy->cbData];
  this->entropy->cbData = entropy.length();
    
  memcpy_s(this->entropy->pbData,sizeof(BYTE),entropy.data(), this->entropy->cbData);
}


ProtectedStorage::~ProtectedStorage()
{
  if (this->entropy != NULL) {
    delete[] this->entropy->pbData;  
  }

  delete this->entropy;
}


bool ProtectedStorage::save(std::string &key, std::string &data)
{
  DATA_BLOB* encryptedData = encrypt(data);
  bool ret = SetRegKeyValue(DEFAULT_REG_ROOT,subkey.c_str(),key.c_str(), encryptedData->pbData, static_cast<int>(encryptedData->cbData));

  LocalFree(encryptedData->pbData);
  delete encryptedData;

  return ret;
}

std::string ProtectedStorage::read(std::string &key)
{  
  bool success = false;
  int size = 0;
  DATA_BLOB input;

  input.pbData = GetRegKeyData(DEFAULT_REG_ROOT,subkey.c_str(),key.c_str(), success, size);

  if (success) {
    input.cbData = static_cast<int>(size);
    std::string returnValue = decrypt(input);

    delete[] input.pbData;

    return returnValue;
  }
  else {
    return std::string ("");
  }
}


DATA_BLOB* ProtectedStorage::encrypt(std::string &data)
{
  DATA_BLOB* output = new DATA_BLOB;
  DATA_BLOB input;
    
  output->cbData = 0;
  input.pbData = (BYTE*) data.data();
  input.cbData = data.length() + 1;

  CryptProtectData(&input, NULL, (DATA_BLOB*) this->entropy, NULL, NULL, 0, output);

  return output;
} 

std::string ProtectedStorage::decrypt(DATA_BLOB& data)
{
  DATA_BLOB output;
  std::string str_output;

  if (CryptUnprotectData(&data, NULL, (DATA_BLOB*) this->entropy, NULL, NULL, 0, &output)) {
    str_output = (char*) output.pbData;  
    LocalFree(output.pbData);

    return str_output;
  }
  else {
    return std::string("");
  }
}