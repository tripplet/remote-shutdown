#include "RemoteShutdown.h"

/** ########## Global variables ########## **/
HANDLE g_StopEvent;
LogFile *logFile;

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;
HANDLE hRxPipeThread;

std::string lastChallange;
time_t lastChallangeTime;

/** ########## Functions ########## **/
bool EnableShutdownPrivNT();
bool enableDEP();
bool isUserLoggedOn();
bool isRemoteUserLoggedIn();
DWORD RxPipe(LPVOID lpParameter);


void ServiceLoop()
{
	WSADATA wsaData;

	// Initialise tcp for windows (winsock)
	auto err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	logFile->writeEntry("Service started");

	hRxPipeThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RxPipe, NULL, 0, NULL);
	hNetTCPThread = StartNetTCPLoopThread(INFORM_PORT);

	// Wait for stop event
	WaitForSingleObject(g_StopEvent, INFINITE);
}

void ServiceQuit()
{
	logFile->writeEntry("Service quit");
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

	if (pchReply == NULL)
	{
		if (pchRequest != NULL)
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
		NULL);                      // default security attribute

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	// Wait for the client to connect; if it succeeds,
	// the function returns a nonzero value. If the function
	// returns zero, GetLastError returns ERROR_PIPE_CONNECTED.
	bool fConnected = ConnectNamedPipe(hPipe, NULL) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);

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
				NULL);                          // not overlapped I/O

			if (!fSuccess || cbBytesRead == 0)
			{
				break;
			}

			ProtectedStorage store(string(PROG_NAME));
			string result;

			if (store.save(string("data"), string(pchRequest)))
			{
				result = string("Secret sucessfully saved");
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
				NULL);        // not overlapped I/O

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

std::string MessageRecieved(const char* message, in_addr ip) {
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
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe
			0,              // default attributes
			NULL);          // no template file

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
		NULL,     // don't set maximum bytes
		NULL);    // don't set maximum time

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
		NULL);          // not overlapped

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
			if (InstallService())
			{
				printf("\n\nService sucessfully installed\nSpecify secret with \"" PROG_NAME " -s SECRET\"\n");
			}
			else
			{
				printf("\n\nError installing service\n");
			}
		}
		else if (strcmp(argv[1], "-d") == 0)
		{
			if (DeleteService())
			{
				printf("\n\nService sucessfully uninstalled\n");
			}
			else
			{
				printf("\n\nError uninstalling service\n");
			}
		}
		else if (strcmp(argv[1], "--debug") == 0)
		{
			printf("\n\nDebug running\n");

			auto hash = sha256::ToHex(*sha256::HashHMAC(std::string("test"), std::string("abcdef")));

			auto secret = CChallengeResponse::createChallange();

			logFile = new LogFile("C:\\Users\\ttobias\\Desktop\\test.txt");
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
				printf("Specify secret with \"" PROG_NAME " -s SECRET\"\n");
			}
		}
		else
		{
			printf("\n\nUnknown switch usage\n\nFor install use \"" PROG_NAME " -i\"\nFor uninstall use \"" PROG_NAME " -d\"\nSpecify secret with \"" PROG_NAME " -s SECRET\"\n");
		}
	}
	else
	{
		SERVICE_TABLE_ENTRY DispatchTable[] = { { PROG_NAME, ServiceMain }, { NULL, NULL } };
		StartServiceCtrlDispatcher(DispatchTable);
	}

	return 0;
}

bool isRemoteUserLoggedIn() {
	PWTS_SESSION_INFO ppSessionInfo = NULL;
	DWORD pCount;

	BOOL bRet = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppSessionInfo, &pCount);

	if (!bRet)
	{
		return false;
	}

	for (DWORD idx = 0; idx < pCount; idx++) {
		if (ppSessionInfo[idx].State == WTSActive)
			return true;
	}

	return false;
}

bool isUserLoggedOn()
{
	HANDLE hToken = NULL;
	HANDLE hDupToken = NULL;

	// Get the user of the "active" session
	DWORD dwSessionId = WTSGetActiveConsoleSessionId();

	if (0xFFFFFFFF == dwSessionId)
	{
		// there is no active session
		return false;
	}

	BOOL ret = WTSQueryUserToken(dwSessionId, &hToken);

	if (NULL == hToken)
	{
		// function call failed
		return false;
	}

	DuplicateToken(hToken, SecurityImpersonation, &hDupToken);

	if (NULL == hDupToken)
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
	if (!LookupPrivilegeValue((LPSTR)NULL, SE_SHUTDOWN_NAME, &DebugValue))
	{
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = DebugValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

	// The return value of AdjustTokenPrivileges can't be tested
	if (GetLastError() != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}
