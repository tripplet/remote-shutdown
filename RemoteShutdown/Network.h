#pragma once

// Includes
#define _WIN32_WINNT NTDDI_WINXP // Wir verwenden Funktionen die ab Windows XP verfügbar sind
#include <windows.h>
#include <winsock.h>
#include <string>

#ifdef _DEBUG
  #include <cstdlib>
#endif

using namespace std;

#include "GlobalConst.h"
#include "RemoteShutdown.h"

#define TCP_MESSAGE 1
#define UDP_MESSAGE 2

// Functionsn
HANDLE StartNetTCPLoopThread(int Port);
HANDLE StartNetUDPLoopThread(int Port);

DWORD netTCPLoop(LPVOID lpParameter);
DWORD netUDPLoop(LPVOID lpParameter);