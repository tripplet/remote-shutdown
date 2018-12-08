#pragma once

#include <windows.h>
#include <string>

namespace registry
{
    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, const std::string &value);
    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, unsigned long value);
    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, const byte *value, unsigned long size);

    int GetKeyInt(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success);
    const std::string GetKeyString(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success);
    byte *GetKeyData(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success, unsigned long &size);
    bool DeleteKey(HKEY mainKey, const std::string &subKey);
    bool DeleteKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName);
}