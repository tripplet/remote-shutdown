#include "Request.h"

#include "GlobalConst.h"
#include "ProtectedStorage.h"
#include "ChallengeResponse.h"
#include "Logger.h"

#include <wtsapi32.h>

#include <ctime>

extern Logger logger;

std::string lastChallange = "";
time_t lastChallangeTime;

Request::Request()
{
}

Request::~Request()
{
}

static bool starts_with(const std::string str, const std::string prefix)
{
    return ((prefix.size() <= str.size()) && std::equal(prefix.begin(), prefix.end(), str.begin()));
}

const std::string Request::HandleMessage(std::string const &message, in_addr ip)
{
    ProtectedStorage store(std::string(PROG_NAME));
    auto secret = store.read("token");

    if (message.empty())
    {
        return "";
    }

    logger.debug(std::string("MessageRechived: ") + message);


    if (message == "ping")
    {
        return "pong";
    }
    else if (message == "request_challange")
    {
        lastChallange = CChallengeResponse::createChallange();

        if (lastChallange.compare("") == 0)
        {
            logger.error("Error in cryptographic module");
            return std::string("internal error");
        }

        lastChallangeTime = time(nullptr);
        return lastChallange;
    }
    else if (starts_with(message, "shutdown.") || starts_with(message, "admin_shutdown"))
    {
        if (secret.empty())
        {
            logger.error("No valid secret found");

            lastChallange.clear();
            return std::string("no token configured in service");
        }

        auto is_admin_shutdown = starts_with(message, "admin_shutdown");
        auto validResponse = !lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange, secret, message);

        lastChallange.clear();
        secret.erase();

        if (validResponse)
        {
            if (difftime(time(nullptr), lastChallangeTime) <= RESPONSE_LIMIT)
            {
                logger.info("Valid shutdown command received");

                if (isUserLoggedOn())
                {
                    logger.info("User logged in");

                    if (!is_admin_shutdown)
                    {
                        return std::string("active user logged in");
                    }
                }

                if (isRemoteUserLoggedIn())
                {
                    logger.info("Remote user logged in");

                    if (!is_admin_shutdown)
                    {
                        return std::string("active user logged in");
                    }
                }

                // Shutdown pc
                Shutdown(30, true);
                logger.info("Shutdown performed");
                return "1";
            }
            else
            {
                return "challenge response to slow";
            }
        }
        else
        {
            return "invalid command";
        }
    }

    return "unknown command";
}

bool Request::isRemoteUserLoggedIn()
{
    PWTS_SESSION_INFO ppSessionInfo = nullptr;
    DWORD pCount;

    const auto result = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppSessionInfo, &pCount);
    if (!result)
    {
        return false;
    }

    for (DWORD idx = 0; idx < pCount; idx++)
    {
        if (ppSessionInfo[idx].State == WTSActive)
        {
            return true;
        }
    }

    return false;
}

bool Request::isUserLoggedOn()
{
    HANDLE token = nullptr;
    HANDLE dupplicatedToken = nullptr;

    // Get the user of the "active" session
    const auto dwSessionId = WTSGetActiveConsoleSessionId();
    if (dwSessionId == 0xFFFFFFFF)
    {
        // there is no active session
        return false;
    }

    const auto ret = WTSQueryUserToken(dwSessionId, &token);
    if (token == nullptr)
    {
        // function call failed
        // TODO
        return false;
    }

    DuplicateToken(token, SecurityImpersonation, &dupplicatedToken);
    if (dupplicatedToken == nullptr)
    {
        CloseHandle(token);
        return false;
    }

    const auto result = ImpersonateLoggedOnUser(dupplicatedToken);
    if (result)
    {
        // Get the username bRes = GetUserNameA(szTempBuf, &dwBufSize);
        // stop impersonating the user
        RevertToSelf();
        return true;
    }

    CloseHandle(dupplicatedToken);
    CloseHandle(token);

    return false;
}

/**
 * Shutdown pc
 */
void Request::Shutdown(unsigned long timeout, bool forceAppsClosed) noexcept
{
    InitiateSystemShutdownEx(nullptr, "Remote system shutdown requested.", timeout, forceAppsClosed, false, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
}