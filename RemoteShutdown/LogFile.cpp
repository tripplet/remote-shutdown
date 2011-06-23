#include "LogFile.h"

LogFile::LogFile(const char *sFileName)
{
	file = new HandleFile(sFileName,HandleFile::AllowRead,HandleFile::ReadWrite,HandleFile::OpenAlways,false);
  newTmpEntry();
}

LogFile::~LogFile(void)
{
	if (file)
		delete file;
}

void LogFile::writeEntry(int iEntry, bool insertTime)
{
	char sBuffer[42];
	itoa(iEntry,sBuffer,10);
	writeEntry(sBuffer,insertTime);
}

void LogFile::writeEntry(const char *sEntry, bool insertTime)
{
  time_t cTime;
  struct tm *strTime;
  char sBuffer[100];
  
  time(&cTime);
  strTime = localtime(&cTime);
  strftime(sBuffer,100,"%d.%m.%Y-%H:%M   ",strTime);
  
	if (insertTime)
		file->appendData(sBuffer,strlen(sBuffer));
	else
		file->appendData("                   ",19);

	file->appendData(sEntry,strlen(sEntry));
	file->appendData("\n",1);
	file->flushData();
}

void LogFile::newTmpEntry()
{
  tmp_entry = "";
}

void LogFile::addTmpEntry(const char *sEntry)
{
  tmp_entry += sEntry;
}

void LogFile::writeTmpEntry(bool insertTime)
{
  writeEntry(tmp_entry.c_str(),insertTime);
  newTmpEntry();
}
