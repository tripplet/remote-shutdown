#pragma once

#include <time.h>
#include <cstdlib>

#include "HandleFile.h"

using namespace std;

class LogFile {
	private:
		HandleFile *file;

	public:
		LogFile(const char *sFileName);
		~LogFile();

		void writeEntry(const char *sEntry, bool insertTime = true);
		void writeEntry(int iEntry, bool insertTime = true);
};
