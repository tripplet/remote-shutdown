#include "HandleFile.h"

HandleFile::~HandleFile()
{
	if (this->m_hFile)
	{
		fclose(m_hFile);
		this->m_hFile = nullptr;
	}

	if (this->m_sFileName)
	{
		delete[] m_sFileName;
		this->m_sFileName = nullptr;
	}
}

HandleFile::HandleFile(const char *fileName, ShareMode eSMode, AccessMode eAMode, CreateFlag eFlag, bool bBinary) {
	bReady = false;
	m_eAMode = eAMode;
	bool bFileExists;
	bool bCreateNewFile = false;
	int iShareFlag;
	char sMode[4];

	this->m_sFileName = new char[strlen(fileName) + 1];
	strncpy(this->m_sFileName, fileName, strlen(fileName) + 1);

	if (this->m_sFileName[0] == '\"')
	{
		size_t sLen = strlen(this->m_sFileName);
		strncpy(this->m_sFileName, this->m_sFileName + 1, strlen(fileName) + 1);
		this->m_sFileName[sLen - 2] = 0;  // Terminiate string
	}

	// Test for existence
	if ((_access(m_sFileName, 0)) == -1)
	{
		bFileExists = false;
	}
	else
	{
		bFileExists = true;
	}


	switch (eFlag) {
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

	switch (eSMode) {
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

	switch (eAMode) {
		case ReadWrite:
			if (bCreateNewFile)
				strncpy(sMode, "w+", 3);
			else
				strncpy(sMode, "r+", 3);
			break;
		case Read:
			strncpy(sMode, "r", 3);
			break;
	}

	if (bBinary)
		strncat(sMode, "b", 3);
	else
		strncat(sMode, "t", 3);

	m_hFile = _fsopen(m_sFileName, sMode, iShareFlag);

	if (m_hFile != 0) {
		bReady = true;
		fseek(m_hFile, 0, SEEK_SET);
	}
}

void HandleFile::getFileName(char *sFileName) {
	strcpy(sFileName, m_sFileName);
}

bool HandleFile::appendData(const void *pData, unsigned int iLength) {
	if (!bReady || m_eAMode != ReadWrite)
		return false;

	fseek(m_hFile, 0, SEEK_END);
	fwrite(pData, iLength, 1, m_hFile);
	return true;
}

bool HandleFile::writeData(const void *pData, unsigned int iLength) {
	if (!bReady || m_eAMode != ReadWrite)
		return false;

	fwrite(pData, iLength, 1, m_hFile);
	return true;
}

bool HandleFile::writeData(const void *pData, unsigned int iLength, unsigned int iPos) {
	if (!bReady || m_eAMode != ReadWrite)
		return false;

	fseek(m_hFile, iPos, SEEK_SET);
	fwrite(pData, iLength, 1, m_hFile);
	return true;
}


bool HandleFile::readData(void *pData, unsigned int iLength) {
	if (!bReady)
		return false;

	fread(pData, iLength, 1, m_hFile);
	return true;
}

bool HandleFile::flushData() {
	if (!bReady)
		return false;

	fflush(m_hFile);

	return true;
}

bool HandleFile::readData(void *pData, unsigned int iLength, unsigned int iPos) {
	if (!bReady)
		return false;

	fseek(m_hFile, iPos, SEEK_SET);
	fread(pData, iLength, 1, m_hFile);
	return true;
}

unsigned int HandleFile::getFileSize() {
	unsigned int iPos, iLength;

	iPos = ftell(m_hFile);
	fseek(m_hFile, 0L, SEEK_END);
	iLength = ftell(m_hFile);
	fseek(m_hFile, iPos, SEEK_SET);

	return iLength;
}
