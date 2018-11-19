#pragma once

#include <windows.h>
#include <string>

bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const int value);
bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const char *value);
bool SetRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName, const BYTE *value, const int size);

int GetRegKeyInt(HKEY hMainKey, const char *subKey, const char *keyName, bool &sucess);
char *GetRegKeyString(HKEY hMainKey, const char *subKey, const char *keyName, bool &sucess);
BYTE *GetRegKeyData(HKEY hMainKey, const char *subKey, const char *keyName, bool &sucess, int &size);

bool DeleteRegKey(HKEY hMainKey ,const char *subKey);
bool DeleteRegKeyValue(HKEY hMainKey, const char *subKey, const char *keyName);

/**
HKEY_CLASSES_ROOT
HKEY_CURRENT_CONFIG
HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE
HKEY_USERS
*/