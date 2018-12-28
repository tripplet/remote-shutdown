#include "RemoteShutdown.h"

HANDLE g_StopEvent;
Logger logger(PROG_NAME);

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;
HANDLE hRxPipeThread;

std::string lastChallange;
time_t lastChallangeTime;

// Functions
bool AquireShutdownPrivilege();
bool isUserLoggedOn();
bool isRemoteUserLoggedIn();
DWORD RxPipe(LPVOID lpParameter);

#include <iostream>
#include <ctime>
#include <algorithm>
#include <string>


void ServiceLoop(bool debugging)
{
    // Init logger
    logger.Init(debugging);

    // Initialize TCP for windows (winsock)
    WSADATA wsaData{};
    auto const err = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (err != 0)
    {
        logger.error(std::string("Initiaizing winsock failed with errorcode: ") + std::to_string(err) + ", exiting");
        return;
    }
    else
    {
        logger.debug("Winsock initialized");
    }

    if (!AquireShutdownPrivilege())
    {
        logger.error("Unable to aquire neccessary privileges, exiting");
        return;
    }
    else
    {
        logger.debug("Shutdown privilege aquired");
    }


    logger.debug("Starting pipe thread...");
    hRxPipeThread = CreateThread(nullptr, 0U, (LPTHREAD_START_ROUTINE)RxPipe, nullptr, 0U, nullptr);

    logger.debug("Starting tcp thread...");
    hNetTCPThread = StartNetTCPLoopThread(DEFAULT_PORT);


    // Wait for stop event
    g_StopEvent = CreateEvent(nullptr, true, false, nullptr);
    if (g_StopEvent == nullptr)
    {
        logger.error("Unable to create wait event, exiting");
        return;
    }

    logger.debug("Service running");
    WaitForSingleObject(g_StopEvent, INFINITE);
}

void ServiceQuit()
{
    TerminateThread(hNetTCPThread, 0);
    TerminateThread(hRxPipeThread, 0);
}

DWORD RxPipe(LPVOID lpParameter)
{
    HANDLE hHeap = GetProcessHeap();
    TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, PIPE_BUFFER_SIZE * sizeof(TCHAR));

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;
    LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\" PROG_NAME "Pipe");

    if (pchRequest == NULL)
    {
        if (pchReply != NULL)
        {
            HeapFree(hHeap, 0, pchReply);
        }

        return -1;
    }

    if (pchReply == nullptr)
    {
        if (pchRequest != nullptr)
        {
            HeapFree(hHeap, 0, pchRequest);
        }

        return -1;
    }

    hPipe = CreateNamedPipe(
        lpszPipename,               // pipe name
        PIPE_ACCESS_DUPLEX,         // read/write access
        PIPE_TYPE_MESSAGE |         // message type pipe
        PIPE_READMODE_MESSAGE |     // message-read mode
        PIPE_WAIT |                 // blocking mode
        PIPE_REJECT_REMOTE_CLIENTS, // deny remote access
        1,                          // max. instances
        PIPE_BUFFER_SIZE,           // output buffer size
        PIPE_BUFFER_SIZE,           // input buffer size
        0,                          // client time-out
        nullptr);                   // default security attribute

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    // Wait for the client to connect; if it succeeds,
    // the function returns a nonzero value. If the function
    // returns zero, GetLastError returns ERROR_PIPE_CONNECTED.
    bool fConnected = ConnectNamedPipe(hPipe, nullptr) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (fConnected)
    {
        // Loop until done reading
        while (true)
        {
            // Read client requests from the pipe. This simplistic code only allows messages
            // up to BUFSIZE characters in length.
            fSuccess = ReadFile(
                hPipe,                          // handle to pipe
                pchRequest,                     // buffer to receive data
                PIPE_BUFFER_SIZE * sizeof(TCHAR), // size of buffer
                &cbBytesRead,                   // number of bytes read
                nullptr);                       // not overlapped I/O

            if (!fSuccess || cbBytesRead == 0)
            {
                break;
            }

            ProtectedStorage store(std::string(PROG_NAME));
            std::string result;

            if (store.save(std::string("token"), std::string(pchRequest)))
            {
                result = std::string("Secret successfully saved");
            }
            else
            {
                result = std::string("Failed to save secret");
            }

            strcpy_s(pchReply, PIPE_BUFFER_SIZE, TEXT(result.c_str()));
            cbReplyBytes = (lstrlen(pchReply) + 1) * sizeof(TCHAR);

            // Write the reply to the pipe.
            fSuccess = WriteFile(
                hPipe,        // handle to pipe
                pchReply,     // buffer to write from
                cbReplyBytes, // number of bytes to write
                &cbWritten,   // number of bytes written
                nullptr);     // not overlapped I/O

            if (!fSuccess || cbReplyBytes != cbWritten)
            {
                // InstanceThread WriteFile failed
                break;
            }
        }

        // Flush the pipe to allow the client to read the pipe's contents
        // before disconnecting. Then disconnect the pipe, and close the
        // handle to this pipe instance.
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        HeapFree(hHeap, 0, pchRequest);
        HeapFree(hHeap, 0, pchReply);

        return 1;
    }

    return -1;
}

static bool starts_with(const std::string str, const std::string prefix)
{
    return ((prefix.size() <= str.size()) && std::equal(prefix.begin(), prefix.end(), str.begin()));
}

const std::string MessageRecieved(std::string const &message, in_addr ip)
{
    ProtectedStorage store(std::string(PROG_NAME));
    auto secret = store.read("token");

    if (message.length() == 0)
    {
        return "";
    }

    logger.debug(std::string("MessageRechived: ") + message);


    if (message == "ping")
    {
        return "pong";
    }

    // challenge request
    if (message == "request_challange")
    {
        lastChallange = CChallengeResponse::createChallange();

        if (lastChallange.compare("") == 0)
        {
            logger.error("Error in cryptographic module");
            return std::string("internal error");
        }

        lastChallangeTime = time(NULL);
        return lastChallange;
    }

    // shutdown
    if (starts_with(message, "shutdown."))
    {
        std::string ret;

        if (secret.compare("") == 0)
        {
            logger.error("No valid secret found");
            return std::string("no token configured in service");
        }

        if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange, secret, message))
        {
            secret.erase();

            if (difftime(time(NULL), lastChallangeTime) <= RESPONSE_LIMIT)
            {
                logger.info("Shutdown command recognized");

                if (isUserLoggedOn())
                {
                    logger.info(" -> User logged in -> ABORT\n");
                    return std::string("USER_LOGGEDIN");
                }

                if (isRemoteUserLoggedIn())
                {
                    logger.info(" -> RemoteUser logged in -> ABORT\n");
                    return std::string("USER_LOGGEDIN");
                }

                logger.info(" -> User not logged in");

                //// get shutdown priv
                //if (!EnableShutdownPrivNT())
                //{
                //    logFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
                //    logFile->writeTmpEntry();
                //    return std::string("FAILED");
                //}

                //logFile->addTmpEntry(" -> ShutdownPriv achieved");

                // Shutdown pc
                ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
                logger.info(" -> Shutdown performed");
                return std::string("1");
            }
            else
            {
                ret = std::string("slow");
            }
        }
        else
        {
            ret = std::string("invalid");
        }

        lastChallange.clear();
        return ret;
    }

    if (starts_with(message, "admin_shutdown."))
    {
        std::string ret;

        if (secret.compare("") == 0)
        {
            logger.error("No valid secret found");
            return std::string("no token configured in service");
        }

        if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange, secret, message))
        {
            secret.erase();

            if (difftime(time(NULL), lastChallangeTime) <= RESPONSE_LIMIT)
            {
                logger.info("Admin Shutdown command recognized");

                if (isUserLoggedOn())
                {
                    logger.info(" -> User logged in");
                }
                else if (isRemoteUserLoggedIn())
                {
                    logger.info(" -> RemoteUser logged in");
                }
                else
                {
                    logger.info(" -> User not logged on");
                }

                //// get shutdown priv
                //if (!EnableShutdownPrivNT())
                //{
                //    logFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
                //    logFile->writeTmpEntry();
                //    return std::string("FAILED");
                //}

                //logFile->addTmpEntry(" -> ShutdownPriv achieved");

                // Shutdown pc
                ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
                logger.info(" -> AdminShutdown performed\n");
                return std::string("1");
            }
            else
            {
                ret = std::string("slow");
            }
        }
        else
        {
            ret = std::string("invalid");
        }

        lastChallange.clear();
        return ret;
    }

    return "unknown command";
}

void setSecret(std::string const &secret)
{
    HANDLE hPipe;
    TCHAR  chBuf[PIPE_BUFFER_SIZE];
    BOOL   fSuccess = FALSE;
    DWORD  cbRead, cbToWrite, cbWritten, dwMode;
    LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\" PROG_NAME "Pipe");

    // Try to open a named pipe; wait for it, if necessary
    while (true)
    {
        hPipe = CreateFile(
            lpszPipename, // pipe name
            GENERIC_READ | GENERIC_WRITE, // read and write access
            0,              // no sharing
            nullptr,        // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            nullptr);       // no template file

        // Break if the pipe handle is valid.
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            break;
        }

        // Exit if an error other than ERROR_PIPE_BUSY occurs.

        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            printf("Error: Could not open pipe. GLE=%d\n", GetLastError());
            return;
        }

        // All pipe instances are busy, so wait for 2 seconds
        if (!WaitNamedPipe(lpszPipename, 2000))
        {
            printf("Could not open pipe: 2 second wait timed out.");
            return;
        }
    }

    // The pipe connected; change to message-read mode
    dwMode = PIPE_READMODE_MESSAGE;

    fSuccess = SetNamedPipeHandleState(
        hPipe,    // pipe handle
        &dwMode,  // new pipe mode
        nullptr,  // don't set maximum bytes
        nullptr); // don't set maximum time

    if (!fSuccess)
    {
        printf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
        return;
    }

    // Send a message to the pipe server
    cbToWrite = static_cast<DWORD>((secret.length() + 1) * sizeof(TCHAR));

    fSuccess = WriteFile(
        hPipe,          // pipe handle
        secret.c_str(), // message
        cbToWrite,      // message length
        &cbWritten,     // bytes written
        nullptr);       // not overlapped

    if (!fSuccess)
    {
        printf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
        return;
    }

    do
    {
        // Read from the pipe
        fSuccess = ReadFile(
            hPipe,    // pipe handle
            chBuf,    // buffer to receive reply
            PIPE_BUFFER_SIZE * sizeof(TCHAR),  // size of buffer
            &cbRead,  // number of bytes read
            NULL);    // not overlapped

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
        {
            break;
        }

        printf(TEXT("\"%s\"\n"), chBuf);
    } while (!fSuccess);  // repeat loop if ERROR_MORE_DATA

    if (!fSuccess)
    {
        printf(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
        return;
    }

    CloseHandle(hPipe);
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        auto parameter = std::string(argv[1]);
        if (parameter == "-i")
        {
            if (InstallCorrespondingService())
            {
                std::cout << "Service successfully installed" << std::endl << "Specify secret with \"" PROG_NAME " -s SECRET\"";
            }
            else
            {
                std::cout << "Error installing service: Try running as administrator";
            }
        }
        else if (parameter == "-r")
        {
            if (DeleteCorrespondingService())
            {
                std::cout << "Service successfully removed";
            }
            else
            {
                std::cout << "Error removing service";
            }
        }
        else if (parameter == "--debug")
        {
            std::cout << "Debug running" << std::endl;

            auto hash = sha256::ToHex(*sha256::HashHMAC(std::string("test"), std::string("abcdef")));
            auto secret = CChallengeResponse::createChallange();

            ServiceLoop(true);
        }
        else if (parameter == "-s")
        {
            if (argc == 3)
            {
                setSecret(std::string(argv[2]));
            }
            else
            {
                std::cout << "Specify secret with \"" PROG_NAME " -s SECRET\"";
            }
        }
        else
        {
            std::cout << "Unknown switch usage\n\nFor install use \"" PROG_NAME " -i\"\nFor removing use \"" PROG_NAME " -r\"\nSpecify secret with \"" PROG_NAME " -s SECRET\"";
        }
    }
    else
    {
        SERVICE_TABLE_ENTRY DispatchTable[] = { { PROG_NAME, ServiceMain }, { nullptr, nullptr } };
        StartServiceCtrlDispatcher(DispatchTable);
    }

    return 0;
}

bool isRemoteUserLoggedIn()
{
    PWTS_SESSION_INFO ppSessionInfo = nullptr;
    DWORD pCount;

    auto result = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppSessionInfo, &pCount);
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

bool isUserLoggedOn()
{
    HANDLE token = nullptr;
    HANDLE dupplicatedToken = nullptr;

    // Get the user of the "active" session
    auto dwSessionId = WTSGetActiveConsoleSessionId();
    if (dwSessionId == 0xFFFFFFFF)
    {
        // there is no active session
        return false;
    }

    auto ret = WTSQueryUserToken(dwSessionId, &token);
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

    auto result = ImpersonateLoggedOnUser(dupplicatedToken);
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
 * Acquire the privilege for shutting down the pc
 * @return True if the privilege could be acquired, false otherwise
 */
bool AquireShutdownPrivilege()
{
    HANDLE token = nullptr;
    LUID luid;

    // Retrieve a handle of the access token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        return false;
    }

    // Lookup the SE_SHUTDOWN_NAME privilege
    if (!LookupPrivilegeValue((LPSTR)nullptr, SE_SHUTDOWN_NAME, &luid))
    {
        return false;
    }

    TOKEN_PRIVILEGES tkp;
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)nullptr, (PDWORD)nullptr);

    // The return value of AdjustTokenPrivileges can't be tested
    return GetLastError() == ERROR_SUCCESS;
}
