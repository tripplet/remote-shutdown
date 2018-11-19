#pragma once

#define _WIN32_WINNT NTDDI_WINXP // Use function available since Windows XP

#include <windows.h>
#include <winsock.h>
#include <string>
#include <exception>

#ifdef _DEBUG
  #include <cstdlib>
#endif

using namespace std;

#include "GlobalConst.h"
#include "RemoteShutdown.h"

// Functions
HANDLE StartNetTCPLoopThread(int port);
DWORD netTCPLoop(LPVOID lpParameter);