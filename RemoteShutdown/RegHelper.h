#pragma once

#include <windows.h>
#include <string>

namespace registry
{
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, DWORD dwType, const byte *value, unsigned long size);
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, std::string const &value);
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, unsigned long value);
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, const byte *value, unsigned long size);

    bool GetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, DWORD dDataLen, BYTE *data);
    bool GetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, DWORD dDataLen, BYTE *data);
    int GetKeyInt(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success);
    const std::string GetKeyString(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success);
    byte *GetKeyData(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success, unsigned long &size);

    DWORD GetKeySize(HKEY mainKey, std::string const &subKey, std::string const &keyName);

    bool DeleteKey(HKEY mainKey, std::string const &subKey);
    bool DeleteKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName);
}