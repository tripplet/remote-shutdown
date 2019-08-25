#pragma once

// Use windows function available from XP and forward
#define _WIN32_WINNT NTDDI_WINXP
#include <windows.h>
#include <winsock.h>
#include <string>

class Request
{


public:

    static const std::string HandleMessage(std::string const &message, in_addr ip);

    static bool Request::isRemoteUserLoggedIn();
    static bool Request::isUserLoggedOn();

    static void Request::Shutdown(unsigned long timeout, bool forceAppsClosed) noexcept;
};

