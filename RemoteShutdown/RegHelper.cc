#include "RegHelper.h"

namespace registry
{
    bool p_SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, DWORD dwType, const byte *value, unsigned long size)
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

    DWORD p_GetKeySize(HKEY mainKey, const std::string &subKey, const std::string &keyName)
    {
        HKEY hKey;
        DWORD dDataSize;
        if (RegCreateKeyEx(mainKey, subKey.c_str(), 0U, nullptr, 0U, KEY_QUERY_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        {
            return 0;
        }

        if (RegQueryValueEx(hKey, keyName.c_str(), 0U, nullptr, nullptr, &dDataSize) != ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return 0;
        }

        RegCloseKey(hKey);
        return dDataSize;
    }

    bool p_GetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, DWORD dDataLen, BYTE *data)
    {
        HKEY hKey;

        if (RegCreateKeyEx(mainKey, subKey.c_str(), 0U, nullptr, 0U, KEY_READ, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        {
            return false;
        }

        if (RegQueryValueEx(hKey, keyName.c_str(), 0U, nullptr, data, &dDataLen) != ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return false;
        }

        RegCloseKey(hKey);
        return true;
    }

    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, const std::string &value)
    {
        return p_SetKeyValue(mainKey, subKey, keyName, REG_SZ, reinterpret_cast<byte*>(const_cast<char*>(value.data())), static_cast<unsigned long>(value.length()));
    }

    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, unsigned long value)
    {
        return p_SetKeyValue(mainKey, subKey, keyName, REG_DWORD, reinterpret_cast<byte*>(&value), sizeof(unsigned long));
    }

    bool SetKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName, const byte *value, unsigned long size)
    {
        return p_SetKeyValue(mainKey, subKey, keyName, REG_BINARY, value, size);
    }

    /** ############################################################## */

    int GetKeyInt(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success)
    {
        DWORD dwData = 0;

        success = p_GetKeyValue(mainKey, subKey, keyName, sizeof(DWORD), reinterpret_cast<byte*>(&dwData));
        return (int)dwData;
    }

    const std::string GetKeyString(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success)
    {
        char *sValue;
        DWORD dDataLen = p_GetKeySize(mainKey, subKey, keyName);

        if (dDataLen == 0)
        {
            success = false;
            return nullptr;
        }

        sValue = new char[dDataLen];

        success = p_GetKeyValue(mainKey, subKey, keyName, dDataLen, reinterpret_cast<byte*>(sValue));

        if (!success)
        {
            delete[] sValue;
            return nullptr;
        }
        else
        {
            return std::string(sValue);
        }
    }

    byte *GetKeyData(HKEY mainKey, const std::string &subKey, const std::string &keyName, bool &success, unsigned long &size)
    {
        BYTE *bValue;
        DWORD dDataLen = p_GetKeySize(mainKey, subKey, keyName);

        if (dDataLen == 0)
        {
            success = false;
            return nullptr;
        }

        bValue = new BYTE[dDataLen];
        success = p_GetKeyValue(mainKey, subKey, keyName, dDataLen, bValue);
        size = (int)dDataLen;

        if (!success)
        {
            delete[] bValue;
            return nullptr;
        }
        else
        {
            return bValue;
        }
    }

    bool DeleteKey(HKEY mainKey, const std::string &subKey)
    {
        return (ERROR_SUCCESS == RegDeleteKey(mainKey, subKey.c_str()));
    }

    bool DeleteKeyValue(HKEY mainKey, const std::string &subKey, const std::string &keyName)
    {
        HKEY hKey;

        if (RegOpenKeyEx(mainKey, subKey.c_str(), 0U, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        {
            return false;
        }

        if (RegDeleteValue(hKey, keyName.c_str()) != ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return false;
        }

        RegCloseKey(hKey);
        return true;
    }

}