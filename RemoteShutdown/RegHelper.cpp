#include "RegHelper.h"

bool p_SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,
                      DWORD dwType,const BYTE *bValue,int iSize) {
  HKEY hKey;
  if (RegCreateKeyEx(hMainKey,sSubKey,
                  0,NULL,0,KEY_WRITE,NULL,&hKey,NULL)!=ERROR_SUCCESS) {
    return false;
  }
  if (RegSetValueEx(hKey,sKeyName,0,dwType,
                    bValue,iSize)!=ERROR_SUCCESS) {
    return false;
  }
  RegCloseKey(hKey);
  return true;
}

DWORD p_GetRegKeySize(HKEY hMainKey,const char *sSubKey,const char *sKeyName) {
  HKEY hKey;
  DWORD dDataSize;
  if (RegCreateKeyEx(hMainKey,sSubKey,
                  0,NULL,0,KEY_QUERY_VALUE,NULL,&hKey,NULL)!=ERROR_SUCCESS) {
    return 0;
  }  
  if (RegQueryValueEx(hKey,sKeyName,0,NULL,NULL,&dDataSize)!=ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return 0;
  }
  RegCloseKey(hKey);
  return dDataSize;
}

bool p_GetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,DWORD dDataLen,BYTE *pData) {
  HKEY hKey;

  if (RegCreateKeyEx(hMainKey,sSubKey,
                  0,NULL,0,KEY_READ,NULL,&hKey,NULL)!=ERROR_SUCCESS) {
    return false;
  }

  if (RegQueryValueEx(hKey,sKeyName,0,NULL,
                      pData,&dDataLen)!=ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return false;
  }

  RegCloseKey(hKey);
  return true;
}

/** ############################################################## */

bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const char *sValue) {
  return  p_SetRegKeyValue(hMainKey,sSubKey,sKeyName,REG_SZ,(LPBYTE)sValue,(DWORD)strlen(sValue)+1);
}

bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const int iValue) {
  DWORD dValue = iValue;
  return  p_SetRegKeyValue(hMainKey,sSubKey,sKeyName,REG_DWORD,(LPBYTE)&dValue,sizeof(DWORD));
}

bool SetRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName,const BYTE *bValue, const int iSize) {
  return  p_SetRegKeyValue(hMainKey,sSubKey,sKeyName,REG_BINARY,bValue,iSize);
}

/** ############################################################## */

int GetRegKeyInt(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess) {
  DWORD dwData=0;

  bSucess = p_GetRegKeyValue(hMainKey,sSubKey,sKeyName,sizeof(DWORD),(BYTE*)&dwData);
  return (int)dwData;
}

char *GetRegKeyString(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess) {
  char *sValue;
  DWORD dDataLen=p_GetRegKeySize(hMainKey,sSubKey,sKeyName);

  if (dDataLen==0) {
    bSucess = false;
    return NULL;
  }

  sValue = new char[dDataLen];

  bSucess = p_GetRegKeyValue(hMainKey,sSubKey,sKeyName,dDataLen,(BYTE*)sValue);

	if (!bSucess) {
		delete[] sValue;
		return NULL;
	}
	else
	  return sValue;
}

BYTE *GetRegKeyData(HKEY hMainKey,const char *sSubKey,const char *sKeyName,bool &bSucess,int &iSize) {
  BYTE *bValue;
  DWORD dDataLen=p_GetRegKeySize(hMainKey,sSubKey,sKeyName);

  if (dDataLen==0) {
    bSucess = false;
    return NULL;
  }

  bValue = new BYTE[dDataLen];
  bSucess = p_GetRegKeyValue(hMainKey,sSubKey,sKeyName,dDataLen,bValue);
  iSize = (int)dDataLen;

	if (!bSucess) {
		delete[] bValue;
		return NULL;
	}
	else
	  return bValue;
}

bool DeleteRegKey(HKEY hMainKey,const char *sSubKey) {
	return (ERROR_SUCCESS==RegDeleteKey(hMainKey,sSubKey));

}

bool DeleteRegKeyValue(HKEY hMainKey,const char *sSubKey,const char *sKeyName) {
  HKEY hKey;

	if (RegOpenKeyEx(hMainKey,sSubKey,0,KEY_SET_VALUE,&hKey)!=ERROR_SUCCESS)
		return false;

	if (RegDeleteValue(hKey,sKeyName)!=ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);

	return true;
}
