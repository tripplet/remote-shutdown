#ifndef REGHELPER_H
#define REGHELPER_H

#include <windows.h>
#include <string>

bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const int sValue);
bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const char *sValue);
bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const BYTE *bValue, const int iSize);

int GetRegKeyInt(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess);
char *GetRegKeyString(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess);
BYTE *GetRegKeyData(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess,int &iSize);

bool DeleteRegKey(HKEY hMainKey,const char *sSubKey);
bool DeleteRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName);

/**
HKEY_CLASSES_ROOT
HKEY_CURRENT_CONFIG
HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE
HKEY_USERS
*/

#endif /** REGHELPER_H*/