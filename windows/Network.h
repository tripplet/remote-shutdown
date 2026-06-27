#pragma once

#define _WIN32_WINNT NTDDI_WINXP // Use function available since Windows XP

#include <windows.h>

// Functions
HANDLE StartNetTCPLoopThread(int port);