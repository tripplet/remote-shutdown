#include "RemoteShutdown.h"

HANDLE g_StopEvent;
Logger logger(PROG_NAME);

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;
HANDLE hRxPipeThread;

std::string lastChallange;
time_t lastChallangeTime;

// Functions
bool EnableShutdownPrivNT();
bool isUserLoggedOn();
bool isRemoteUserLoggedIn();
DWORD RxPipe(LPVOID lpParameter);

#include <iostream>


void ServiceLoop()
{
    // Initialize TCP for windows (winsock)
    WSADATA wsaData;
    auto const err = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (err != 0)
    {
        return;
    }

    hRxPipeThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)RxPipe, nullptr, 0, nullptr);
    hNetTCPThread = StartNetTCPLoopThread(DEFAULT_PORT);

    // Wait for stop event
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

            ProtectedStorage store(string(PROG_NAME));
            string result;

            if (store.save(string("token"), string(pchRequest)))
            {
                result = string("Secret successfully saved");
            }
            else
            {
                result = string("Failed to save secret");
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

std::string MessageRecieved(const char* message, in_addr ip)
{
    DWORD bufCharCount = MAX_COMPUTERNAME_LENGTH + 1;
    char *sMessage = new char[strlen(message) + 1];

    ProtectedStorage store(string(PROG_NAME));

    if (strlen(message) == 0)
    {
        return std::string("EMPTY");
    }

    logFile->newTmpEntry();
    logFile->addTmpEntry("MessageRechived ");

    logFile->addTmpEntry("(TCP): ");

    if (strlen(message) > 20)
    {
        logFile->addTmpEntry(message, 20);
        logFile->addTmpEntry("...");
    }
    else
    {
        logFile->addTmpEntry(message);
    }

    logFile->writeTmpEntry();

    strncpy(sMessage, message, strlen(message) + 1);
    strlwr(sMessage);

    // challange request
    if (0 == strcmpi(sMessage, "request_shutdown"))
    {
        lastChallange = CChallengeResponse::createChallange();

        if (lastChallange.compare("") == 0)
        {
            logFile->newTmpEntry();
            logFile->addTmpEntry("Error in cryptographic module");
            logFile->writeTmpEntry();
            return std::string("INTERNAL ERROR");
        }

        lastChallangeTime = time(NULL);
        return lastChallange;
    }

    // shutdown
    if (0 == strnicmp(sMessage, "shutdown", 8))
    {
        std::string ret;
        std::string secret = store.read(string("data"));

        if (secret.compare("") == 0)
        {
            logFile->newTmpEntry();
            logFile->addTmpEntry("No valid secret found");
            logFile->writeTmpEntry();
            return std::string("INTERNAL ERROR");
        }

        if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange, secret, std::string(sMessage + 9)))
        {

            secret.erase();

            if (difftime(time(NULL), lastChallangeTime) <= RESPONSE_LIMIT)
            {
                delete[] sMessage;

                logFile->newTmpEntry();
                logFile->addTmpEntry("Shutdown command recognized");

                if (isUserLoggedOn())
                {
                    logFile->addTmpEntry(" -> User logged in -> ABORT\n");
                    logFile->writeTmpEntry();
                    return std::string("USER_LOGGEDIN");
                }

                if (isRemoteUserLoggedIn())
                {
                    logFile->addTmpEntry(" -> RemoteUser logged in -> ABORT\n");
                    logFile->writeTmpEntry();
                    return std::string("USER_LOGGEDIN");
                }

                logFile->writeEntry(" -> User not logged in");

                // get shutdown priv
                if (!EnableShutdownPrivNT())
                {
                    logFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
                    logFile->writeTmpEntry();
                    return std::string("FAILED");
                }

                logFile->addTmpEntry(" -> ShutdownPriv achieved");

                // Shutdown pc
                ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
                logFile->addTmpEntry(" -> Shutdown performed");
                logFile->writeTmpEntry();
                return std::string("1");
            }
            else
            {
                ret = std::string("SLOW");
            }
        }
        else
        {
            ret = std::string("INVALID");
        }

        lastChallange.clear();
        return ret;
    }

    if (0 == strnicmp(sMessage, "admin_shutdown", 14))
    {
        std::string ret;
        std::string secret = store.read(string("data"));

        if (secret.compare("") == 0)
        {
            logFile->newTmpEntry();
            logFile->addTmpEntry("No valid secret found");
            logFile->writeTmpEntry();
            return std::string("INTERNAL ERROR");
        }

        if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange, secret, std::string(sMessage + 15)))
        {
            secret.erase();

            if (difftime(time(NULL), lastChallangeTime) <= RESPONSE_LIMIT)
            {
                delete[] sMessage;

                logFile->newTmpEntry();
                logFile->addTmpEntry("Admin Shutdown command recognized");

                if (isUserLoggedOn())
                {
                    logFile->addTmpEntry(" -> User logged in");
                }
                else if (isRemoteUserLoggedIn())
                {
                    logFile->addTmpEntry(" -> RemoteUser logged in");
                }
                else
                {
                    logFile->addTmpEntry(" -> User not logged on");
                }

                // get shutdown priv
                if (!EnableShutdownPrivNT())
                {
                    logFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
                    logFile->writeTmpEntry();
                    return std::string("FAILED");
                }

                logFile->addTmpEntry(" -> ShutdownPriv achieved");

                // Shutdown pc
                ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
                logFile->writeEntry(" -> AdminShutdown performed\n");
                logFile->writeTmpEntry();
                return std::string("1");
            }
            else
            {
                ret = std::string("SLOW");
            }
        }
        else
        {
            ret = std::string("INVALID");
        }

        lastChallange.clear();
        return ret;
    }

    return std::string("NOT_RECOGNIZED");
}

void setSecret(string &secret)
{
    HANDLE hPipe;
    TCHAR  chBuf[PIPE_BUFFER_SIZE];
    BOOL   fSuccess = FALSE;
    DWORD  cbRead, cbToWrite, cbWritten, dwMode;
    LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\" PROG_NAME "Pipe");

    // Try to open a named pipe; wait for it, if necessary
    while (1)
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
    cbToWrite = (secret.length() + 1) * sizeof(TCHAR);

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
        if (strcmp(argv[1], "-i") == 0)
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
        else if (strcmp(argv[1], "-d") == 0)
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
        else if (strcmp(argv[1], "--debug") == 0)
        {
            std::cout << "Debug running";

            auto hash = sha256::ToHex(*sha256::HashHMAC(std::string("test"), std::string("abcdef")));
            auto secret = CChallengeResponse::createChallange();

            ServiceLoop();
        }
        else if (strcmp(argv[1], "-s") == 0)
        {
            if (argc == 3)
            {
                setSecret(string(argv[2]));
            }
            else
            {
                std::cout << "Specify secret with \"" PROG_NAME " -s SECRET\"";
            }
        }
        else
        {
            std::cout << "Unknown switch usage\n\nFor install use \"" PROG_NAME " -i\"\nFor removing use \"" PROG_NAME " -d\"\nSpecify secret with \"" PROG_NAME " -s SECRET\"";
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

    BOOL bRet = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppSessionInfo, &pCount);

    if (!bRet)
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
    HANDLE hToken = nullptr;
    HANDLE hDupToken = nullptr;

    // Get the user of the "active" session
    DWORD dwSessionId = WTSGetActiveConsoleSessionId();

    if (0xFFFFFFFF == dwSessionId)
    {
        // there is no active session
        return false;
    }

    BOOL ret = WTSQueryUserToken(dwSessionId, &hToken);

    if (nullptr == hToken)
    {
        // function call failed
        return false;
    }

    DuplicateToken(hToken, SecurityImpersonation, &hDupToken);

    if (nullptr == hDupToken)
    {
        CloseHandle(hToken);
        return false;
    }

    BOOL bRes = ImpersonateLoggedOnUser(hDupToken);

    if (bRes)
    {
        // Get the username bRes = GetUserNameA(szTempBuf, &dwBufSize);
        // stop impersonating the user
        RevertToSelf();
        return true;
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);

    return false;
}


bool EnableShutdownPrivNT()
{
    HANDLE hToken;
    LUID DebugValue;
    TOKEN_PRIVILEGES tkp;

    // Retrieve a handle of the access token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return false;
    }

    // Enable the SE_DEBUG_NAME privilege
    if (!LookupPrivilegeValue((LPSTR)nullptr, SE_SHUTDOWN_NAME, &DebugValue))
    {
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = DebugValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)nullptr, (PDWORD)nullptr);

    // The return value of AdjustTokenPrivileges can't be tested
    if (GetLastError() != ERROR_SUCCESS)
    {
        return false;
    }

    return true;
}
