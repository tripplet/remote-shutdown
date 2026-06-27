#pragma once

#include <cstdio>
#include <io.h>
#include <share.h>
#include <string.h>

using namespace std;

class HandleFile {
  public:
    typedef enum {
      ExclusiveAccess,
      AllowRead,
      ShareAccess
    }ShareMode;

    typedef enum {
      OpenExisting,
      OpenAlways,
      CreateNew,
      CreateNewAlways
    } CreateFlag;

    typedef enum {
      ReadWrite,
      Read
    }AccessMode;

  private:
    FILE *m_hFile;
    AccessMode m_eAMode;
    bool bReady;
    char *m_sFileName;

  public:
    HandleFile(const char *sFileName, ShareMode eSMode, AccessMode eAMode, CreateFlag eFlag, bool bBinary=true);

    ~HandleFile();

    bool initSuccessfull() {return bReady;}
    void getFileName(char *sFileName);

    bool appendData(const void *pData,unsigned int iLength);
    bool writeData(const void *pData,unsigned int iLength);
    bool writeData(const void *pData,unsigned int iLength,unsigned int iPos);
    bool readData(void *pData,unsigned int iLength);
    bool readData(void *pData,unsigned int iLength,unsigned int iPos);

		bool flushData();

    unsigned int getFileSize();
};
