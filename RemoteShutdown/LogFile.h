#pragma once

#include <time.h>
#include <cstdlib>
#include <string>

#include "HandleFile.h"

class LogFile {
	private:
    HandleFile *file;
    std::string tmp_entry;

	public:
		LogFile(const char *sFileName);
		~LogFile();

		void writeEntry(const char *sEntry, bool insertTime = true);
		void writeEntry(int iEntry, bool insertTime = true);

    void newTmpEntry();
    void addTmpEntry(const char *sEntry);
    void writeTmpEntry(bool insertTime = true);
};
