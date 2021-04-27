#pragma once

#include <windows.h>
#include <string>

namespace registry
{
    inline bool SetKeyValue(HKEY mainKey, std::string const& subKey, std::string const& keyName, DWORD dwType, const byte* value, unsigned long size) noexcept
    {
        HKEY hKey;
        if (RegCreateKeyEx(mainKey, subKey.c_str(), 0U, nullptr, 0U, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        {
            return false;
        }

        if (RegSetValueEx(hKey, keyName.c_str(), 0U, dwType, value, size) != ERROR_SUCCESS)
        {
            return false;
        }

        RegCloseKey(hKey);
        return true;
    }

    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, std::string const &value);
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, unsigned long value);
    bool SetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, const byte *value, unsigned long size);

    bool GetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, DWORD dDataLen, BYTE *data) noexcept;
    bool GetKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName, DWORD dDataLen, BYTE *data) noexcept;
    int GetKeyInt(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success);
    const std::string GetKeyString(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success);
    byte *GetKeyData(HKEY mainKey, std::string const &subKey, std::string const &keyName, bool &success, unsigned long &size);

    DWORD GetKeySize(HKEY mainKey, std::string const &subKey, std::string const &keyName) noexcept;

    bool DeleteKey(HKEY mainKey, std::string const &subKey) noexcept;
    bool DeleteKeyValue(HKEY mainKey, std::string const &subKey, std::string const &keyName) noexcept;
}