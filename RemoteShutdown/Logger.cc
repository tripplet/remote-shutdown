#include "Logger.h"

#include <Windows.h>

Logger::Logger(const char *name)
{
	this->eventSource = RegisterEventSource(nullptr, name);
}

Logger::~Logger()
{
	if (this->eventSource)
	{
		DeregisterEventSource(this->eventSource);
	}
}

void Logger::info(const char *message)
{
	LPCSTR messageArray[1] = { message };
	ReportEvent(this->eventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, nullptr, 1, 0, messageArray, NULL);
}

void Logger::warn(const char *message)
{
	LPCSTR messageArray[1] = { message };
	ReportEvent(this->eventSource, EVENTLOG_WARNING_TYPE, 0, 0, nullptr, 1, 0, messageArray, NULL);
}

void Logger::error(const char *message)
{
	LPCSTR messageArray[1] = { message };
	ReportEvent(this->eventSource, EVENTLOG_ERROR_TYPE, 0, 0, nullptr, 1, 0, messageArray, NULL);
}