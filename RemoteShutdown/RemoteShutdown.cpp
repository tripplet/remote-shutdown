#include "RemoteShutdown.h"

#include "Network.h"
#include "ProtectedStorage.h"
#include "ChallengeResponse.h"

#include <iostream>
#include <ctime>
#include <algorithm>
#include <string>

HANDLE g_StopEvent;
Logger logger(PROG_NAME);


HANDLE tcpThread;
HANDLE rxPipeThread;

// Functions
bool AquirePrivileges();
DWORD RxPipe(LPVOID lpParameter);

void ServiceLoop(bool debugging)
{
    // Init logger
    logger.Init(debugging);

    // Initialize TCP for windows (winsock)
    WSADATA wsaData{};
    auto const err = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (err != 0)
    {
        logger.error(std::string("Initializing winsock failed with error code: ") + std::to_string(err) + ", exiting");
        return;
    }
    else
    {
        logger.debug("Winsock initialized");
    }

    if (!AquirePrivileges())
    {
        logger.error("Unable to acquire necessary privileges, exiting");
        return;
    }
    else
    {
        logger.debug("Shutdown privilege acquired");
    }

    logger.debug("Starting pipe thread...");
    rxPipeThread = CreateThread(nullptr, 0U, (LPTHREAD_START_ROUTINE)RxPipe, nullptr, 0U, nullptr);

    logger.debug("Starting TCP thread...");
    tcpThread = StartNetTCPLoopThread(DEFAULT_PORT);

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
    TerminateThread(tcpThread, 0);
    TerminateThread(rxPipeThread, 0);
}

DWORD RxPipe(LPVOID lpParameter)
{
    HANDLE hHeap = GetProcessHeap();
    TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    ZeroMemory(pchRequest, PIPE_BUFFER_SIZE * sizeof(TCHAR));

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;
    const LPTSTR lpszPipename = PIPE_NAME;

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
        logger.error("Unable to create pipe");
        return -1;
    }

    while (true)
    {
        // Wait for the client to connect; if it succeeds,
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED.
        bool fConnected = ConnectNamedPipe(hPipe, nullptr) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!fConnected)
        {
            break;
        }

        // Loop until done reading
        while (true)
        {
            // Read client requests from the pipe. This simplistic code only allows messages
            // up to BUFSIZE characters in length.
            fSuccess = ReadFile(
                hPipe,                                // handle to pipe
                pchRequest,                           // buffer to receive data
                PIPE_BUFFER_SIZE * sizeof(TCHAR) - 1, // size of buffer
                &cbBytesRead,                         // number of bytes read
                nullptr);                             // not overlapped I/O

            if (!fSuccess || cbBytesRead == 0)
            {
                break;
            }

			std::string result;
			if (std::string(pchRequest) == "generate_token")
			{
				auto newSecret = CChallengeResponse::createChallange();

				ProtectedStorage store(std::string(PROG_NAME));
				if (store.save(std::string("token"), newSecret))
				{
					result = "New token is: " + newSecret;
				}
				else
				{
					result = std::string("Failed to save token");
				}
			}
			else
			{
				result = std::string("Unknown command");
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
    }

    HeapFree(hHeap, 0, pchRequest);
    HeapFree(hHeap, 0, pchReply);

    return -1;
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
                std::cout << "Service successfully installed";

                if (StartCorrespondingService())
                {
                    std::cout << " and started." << std::endl << "Generate token with \"" PROG_NAME " -t\"";
                }
                else
                {
                    std::cout << " but service could not be started!" << std::endl;
                }
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
            std::cout << "Debug service running in foreground..." << std::endl;
            ServiceLoop(true);
        }
        else if (parameter == "-t")
        {
            SendMessageToService("generate_token");
		}
        else
        {
            std::cout << "Unknown switch usage\n\nFor install use \"" PROG_NAME " -i\"\nFor removing use \"" PROG_NAME " -r\"\nGenerate token with \"" PROG_NAME " -t\"";
        }
    }
    else
    {
        SERVICE_TABLE_ENTRY DispatchTable[] = { { PROG_NAME, ServiceMain }, { nullptr, nullptr } };
        StartServiceCtrlDispatcher(DispatchTable);
    }

    return 0;
}



bool AreLUIDsEqual(LUID luid1, LUID luid2) noexcept
{
    return luid1.LowPart == luid2.LowPart && luid1.HighPart == luid2.HighPart;
}

std::string GetLastErrorAsString()
{
    const DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
    {
        return std::string();
    }
    else
    {
        return std::system_category().message(errorMessageID);
    }
}

/**
 * Acquire the shutdown privilege and drop all other privileges.
 * @return True if the privileges could be acquired, false otherwise
 */
bool AquirePrivileges()
{
    // Lookup the SE_SHUTDOWN_NAME privilege
    LUID luid_shutdown;
    if (!LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &luid_shutdown))
    {
        return false;
    }

    HANDLE token = nullptr;

    // Retrieve a handle of the access token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ | TOKEN_WRITE, &token))
    {
        CloseHandle(token);
        return false;
    }

    // Get the required buffer size for the TokenPrivileges
    DWORD sizeof_privileges = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &sizeof_privileges);
    if (sizeof_privileges == 0)
    {
        CloseHandle(token);
        return false;
    }

    // Allocate TokenPrivileges struct and get them
    auto privilegeBuffer = std::make_unique<byte[]>(sizeof_privileges);
    auto privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(privilegeBuffer.get());

    if (!GetTokenInformation(token, TokenPrivileges, privileges, sizeof_privileges, &sizeof_privileges))
    {
        CloseHandle(token);
        return false;
    }

    for (size_t i = 0; i < privileges->PrivilegeCount; i++)
    {
        if (AreLUIDsEqual(luid_shutdown, privileges->Privileges[i].Luid))
        {
            privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        else
        {
            privileges->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
        }
    }

    AdjustTokenPrivileges(token, false, privileges, 0, nullptr, nullptr);

    // The return value of AdjustTokenPrivileges can't be tested
    if (GetLastError() != ERROR_SUCCESS)
    {
        CloseHandle(token);
        return false;
    }
    else
    {
        CloseHandle(token);
        return true;
    }
}