#pragma once

#include <windows.h>
#include <string>

class Logger
{
private:
	HANDLE eventSource = nullptr;
    std::string name;
    bool debugging = false;

    void WriteToConsole(std::string const &message);

public:
	explicit Logger(std::string const &name);
	~Logger();

    void init(bool debugging);

    void debug(std::string const &message);
    void info(std::string const &message);
    void warn(std::string const &message);
    void error(std::string const &message);
};
