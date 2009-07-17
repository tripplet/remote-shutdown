#include "HandleFile.h"

HandleFile::~HandleFile() {
  if (m_hFile!=NULL)
    fclose(m_hFile);
  if (m_sFileName)
    delete[] m_sFileName;
}

HandleFile::HandleFile(const char *sFileName, ShareMode eSMode, AccessMode eAMode, CreateFlag eFlag, bool bBinary) {
  bReady = false;
  m_eAMode = eAMode;
  bool bFileExists;
  bool bCreateNewFile = false;
  int iShareFlag;
  char sMode[4];

  m_sFileName = new char[strlen(sFileName)+1];
  strcpy(m_sFileName,sFileName);

  if (m_sFileName[0]=='\"') {
    size_t sLen=strlen(m_sFileName);    
    strcpy(m_sFileName,m_sFileName+1);
    m_sFileName[sLen-2]=0;  // Terminiate string 
  }

  /* Test for existence */
  if( (_access(m_sFileName, 0 )) == -1 )  
    bFileExists = false;
  else   
    bFileExists = true;
  
  switch(eFlag) {
    case OpenExisting:
      if (!bFileExists)
        return;
      break;

    case OpenAlways:
      if (!bFileExists)
        bCreateNewFile = true;
      break;

    case CreateNew:
      if (bFileExists)
        return;
      else
        bCreateNewFile = true;
      break;

    case CreateNewAlways:
      bCreateNewFile = true;
      break;
  }

  switch(eSMode) {
    case ExclusiveAccess:
      iShareFlag = _SH_DENYRW;
      break;
    case AllowRead:
      iShareFlag = _SH_DENYWR;
      break;
    default:
    case ShareAccess:
      iShareFlag = _SH_DENYNO;
      break;
  }

  switch(eAMode) {
    case ReadWrite:
      if (bCreateNewFile)
        strcpy(sMode,"w+");
      else
        strcpy(sMode,"r+");
      break;
    case Read:
      strcpy(sMode,"r");
      break;
  }

  if (bBinary)
    strcat(sMode,"b");
  else
    strcat(sMode,"t");

  m_hFile = _fsopen(m_sFileName,sMode,iShareFlag);

  if (m_hFile!=0) {
    bReady = true;
    fseek(m_hFile,0,SEEK_SET);
  }
}

void HandleFile::getFileName(char *sFileName) {
  strcpy(sFileName,m_sFileName);
}

bool HandleFile::appendData(const void *pData,unsigned int iLength) {
  if (!bReady || m_eAMode!=ReadWrite)
    return false;
  
  fseek(m_hFile,0,SEEK_END);
  fwrite(pData,iLength,1,m_hFile);  
  return true;
}

bool HandleFile::writeData(const void *pData,unsigned int iLength) {
  if (!bReady || m_eAMode!=ReadWrite)
    return false;
  
  fwrite(pData,iLength,1,m_hFile);  
  return true;
}

bool HandleFile::writeData(const void *pData,unsigned int iLength,unsigned int iPos) {
  if (!bReady || m_eAMode!=ReadWrite)
    return false;

  fseek(m_hFile,iPos,SEEK_SET);  
  fwrite(pData,iLength,1,m_hFile);  
  return true;
}


bool HandleFile::readData(void *pData,unsigned int iLength) {
  if (!bReady)
    return false;

  fread(pData,iLength,1,m_hFile);
  return true;
}

bool HandleFile::flushData() {
  if (!bReady)
    return false;

	fflush(m_hFile);

	return true;
}

bool HandleFile::readData(void *pData,unsigned int iLength,unsigned int iPos) {
  if (!bReady)
    return false;

  fseek(m_hFile,iPos,SEEK_SET);  
  fread(pData,iLength,1,m_hFile);
  return true;
}

unsigned int HandleFile::getFileSize() {
  unsigned int iPos, iLength;

  iPos = ftell(m_hFile); 
  fseek (m_hFile, 0L, SEEK_END);
  iLength = ftell(m_hFile);
  fseek(m_hFile,iPos,SEEK_SET);

  return iLength;
}
