#include "LogFile.h"

LogFile::LogFile(const char *fileName)
{
	this->file = new HandleFile(fileName, HandleFile::AllowRead, HandleFile::ReadWrite, HandleFile::OpenAlways, false);
	newTmpEntry();
}

LogFile::~LogFile(void)
{
	if (this->file)
	{
		delete this->file;
		this->file = nullptr;
	}
}

void LogFile::writeEntry(int iEntry, bool insertTime)
{
	char sBuffer[42];
	itoa(iEntry, sBuffer, 10);
	writeEntry(sBuffer, insertTime);
}

void LogFile::writeEntry(const char *sEntry, bool insertTime)
{
	time_t cTime;
	struct tm *strTime;
	char sBuffer[100];

	time(&cTime);
	strTime = localtime(&cTime);
	strftime(sBuffer, 100, "%d.%m.%Y-%H:%M   ", strTime);

	if (insertTime)
		file->appendData(sBuffer, strlen(sBuffer));
	else
		file->appendData("                   ", 19);

	file->appendData(sEntry, strlen(sEntry));
	file->appendData("\n", 1);
	file->flushData();
}

void LogFile::newTmpEntry()
{
	this->tmp_entry = "";
}

void LogFile::addTmpEntry(const char *sEntry)
{
	this->tmp_entry.append(sEntry);
}

void LogFile::addTmpEntry(const char *sEntry, unsigned int length)
{
	this->tmp_entry.append(sEntry, 0, length);
}

void LogFile::writeTmpEntry(bool insertTime)
{
	this->writeEntry(this->tmp_entry.c_str(), insertTime);
	newTmpEntry();
}
