#include "RegHelper.h"

bool p_SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, DWORD dwType, const BYTE *value, int size)
{
	HKEY hKey;
	if (RegCreateKeyEx(hMainKey, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegSetValueEx(hKey, keyName, 0, dwType, value, size) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

DWORD p_GetRegKeySize(HKEY hMainKey, const char *subKey, const char *keyName)
{
	HKEY hKey;
	DWORD dDataSize;
	if (RegCreateKeyEx(hMainKey, subKey, 0, NULL, 0, KEY_QUERY_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
		return 0;
	}

	if (RegQueryValueEx(hKey, keyName, 0, NULL, NULL, &dDataSize) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return 0;
	}

	RegCloseKey(hKey);
	return dDataSize;
}

bool p_GetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, DWORD dDataLen, BYTE *data)
{
	HKEY hKey;

	if (RegCreateKeyEx(hMainKey, subKey, 0, NULL, 0, KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegQueryValueEx(hKey, keyName, 0, NULL, data, &dDataLen) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const char *value)
{
	return p_SetRegKeyValue(hMainKey, subKey, keyName, REG_SZ, (LPBYTE)value, (DWORD)strlen(value) + 1);
}

bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const int iValue)
{
	DWORD dValue = iValue;
	return p_SetRegKeyValue(hMainKey, subKey, keyName, REG_DWORD, (LPBYTE)&dValue, sizeof(DWORD));
}

bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const BYTE *value, const int size)
{
	return p_SetRegKeyValue(hMainKey, subKey, keyName, REG_BINARY, value, size);
}

/** ############################################################## */

int GetRegKeyInt(HKEY hMainKey, const char *subKey, const char *keyName, bool &success)
{
	DWORD dwData = 0;

	success = p_GetRegKeyValue(hMainKey, subKey, keyName, sizeof(DWORD), (BYTE*)&dwData);
	return (int)dwData;
}

char *GetRegKeyString(HKEY hMainKey, const char *subKey, const char *keyName, bool &success) {
	char *sValue;
	DWORD dDataLen = p_GetRegKeySize(hMainKey, subKey, keyName);

	if (dDataLen == 0)
	{
		success = false;
		return nullptr;
	}

	sValue = new char[dDataLen];

	success = p_GetRegKeyValue(hMainKey, subKey, keyName, dDataLen, (BYTE*)sValue);

	if (!success)
	{
		delete[] sValue;
		return nullptr;
	}
	else
	{
		return sValue;
	}
}

BYTE *GetRegKeyData(HKEY hMainKey, const char *subKey, const char *keyName, bool &success, int &size)
{
	BYTE *bValue;
	DWORD dDataLen = p_GetRegKeySize(hMainKey, subKey, keyName);

	if (dDataLen == 0)
	{
		success = false;
		return NULL;
	}

	bValue = new BYTE[dDataLen];
	success = p_GetRegKeyValue(hMainKey, subKey, keyName, dDataLen, bValue);
	size = (int)dDataLen;

	if (!success)
	{
		delete[] bValue;
		return NULL;
	}
	else
	{
		return bValue;
	}
}

bool DeleteRegKey(HKEY hMainKey, const char *subKey)
{
	return (ERROR_SUCCESS == RegDeleteKey(hMainKey, subKey));
}

bool DeleteRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName)
{
	HKEY hKey;

	if (RegOpenKeyEx(hMainKey, subKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(hKey, keyName) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);

	return true;
}
