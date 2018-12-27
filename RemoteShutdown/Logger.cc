#include "Logger.h"

#include <Windows.h>
#include <iostream>

Logger::Logger(const std::string &name)
{
    this->name = name;
}

Logger::~Logger()
{
	if (this->eventSource)
	{
		DeregisterEventSource(this->eventSource);
	}
}

void Logger::Init(bool debugging)
{
    this->debugging = debugging;
    this->eventSource = RegisterEventSource(nullptr, this->name.c_str());
}

void Logger::WriteToConsoleWhileDebugging(std::string const &message)
{
    if (this->debugging)
    {
        std::cout << message << std::endl;
    }
}

void Logger::info(std::string const &message)
{
	LPCSTR messageArray[1] = { message.c_str() };
	ReportEvent(this->eventSource, EVENTLOG_INFORMATION_TYPE, 0U, 0U, nullptr, 1, 0U, messageArray, nullptr);

    this->WriteToConsoleWhileDebugging(std::string("INFO: ") + message);
}

void Logger::warn(std::string const &message)
{
	LPCSTR messageArray[1] = { message.c_str() };
	ReportEvent(this->eventSource, EVENTLOG_WARNING_TYPE, 0U, 0U, nullptr, 1, 0U, messageArray, nullptr);

    this->WriteToConsoleWhileDebugging(std::string("WARN: ") + message);
}

void Logger::error(std::string const &message)
{
	LPCSTR messageArray[1] = { message.c_str() };
	ReportEvent(this->eventSource, EVENTLOG_ERROR_TYPE, 0U, 0U, nullptr, 1, 0U, messageArray, nullptr);

    this->WriteToConsoleWhileDebugging(std::string("ERROR: ") + message);
}

void Logger::debug(std::string const &message)
{
    this->WriteToConsoleWhileDebugging(std::string("DEBUG: ") + message);
}

