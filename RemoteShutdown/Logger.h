#pragma once

#include <windows.h>

class Logger
{
private:
	HANDLE eventSource = nullptr;

public:
	explicit Logger(const char *name);
	~Logger();

	void info(const char *message);
	void warn(const char *message);
	void error(const char *message);
};
