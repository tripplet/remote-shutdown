#pragma once

#include <winsock.h>
#include <string>

class Request
{


public:
    Request();
    ~Request();

    static const std::string HandleMessage(std::string const &message, in_addr ip);

    static bool Request::isRemoteUserLoggedIn();
    static bool Request::isUserLoggedOn();

    static void Request::Shutdown(unsigned long timeout, bool forceAppsClosed) noexcept;
};

